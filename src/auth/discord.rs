//! "Continue with Discord" for the desktop app.
//!
//! 1. The app calls `POST /v1/auth/discord/start` with a random poll secret's hash and
//!    opens the returned URL in the system browser.
//! 2. Discord redirects the browser to `/v1/auth/discord/callback`; the server swaps the
//!    code for the Discord profile (the client secret never leaves the server), creates
//!    or updates the account and shows "You're signed in, return to Distanplay".
//! 3. The app polls `POST /v1/auth/poll` with the secret and receives its tokens.
//!
//! No custom URL scheme or local web server is needed, and a code intercepted in the
//! browser is useless without the poll secret that only the app holds.

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{audit, issue, random_token, sha256};
use crate::error::{ApiError, ApiResult, bad};
use crate::routes::me::{MeResponse, load_me};
use crate::{AppState, client_ip, username};

const LOGIN_TTL: Duration = Duration::minutes(10);

#[derive(Deserialize)]
pub struct DeviceInfo {
    pub install_id: Uuid,
    pub name: String,
    pub platform: String,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
}

#[derive(Deserialize)]
pub struct StartRequest {
    pub device: DeviceInfo,
    /// base64url(SHA-256(poll_secret)); the app keeps the secret.
    pub poll_challenge: String,
}

#[derive(Serialize)]
pub struct StartResponse {
    pub login_id: Uuid,
    pub authorize_url: String,
    pub expires_in: i64,
    pub poll_interval_ms: u64,
}

pub fn platform(p: &str) -> &'static str {
    match p.to_ascii_lowercase().as_str() {
        "windows" => "windows",
        "macos" | "mac" | "darwin" => "macos",
        "linux" => "linux",
        "android" => "android",
        "ios" => "ios",
        "web" => "web",
        _ => "other",
    }
}

pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<StartRequest>,
) -> ApiResult<Json<StartResponse>> {
    use base64::Engine;
    state.limits.check("login_start", client_ip(&headers, addr), 10)?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.poll_challenge.trim())
        .ok()
        .filter(|c| c.len() == 32)
        .ok_or_else(|| bad("invalid_challenge", "poll_challenge must be base64url(SHA-256(secret))"))?;
    let name: String = req.device.name.trim().chars().take(64).collect();
    if name.is_empty() {
        return Err(bad("invalid_device", "device name is required"));
    }
    let state_token = random_token("");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO login_requests (provider, state_hash, poll_secret_hash, install_id, device_name, platform, os_version, app_version, ip, expires_at)
         VALUES ('discord', $1, $2, $3, $4, $5::device_platform, $6, $7, $8, $9) RETURNING id",
    )
    .bind(sha256(&state_token))
    .bind(challenge)
    .bind(req.device.install_id)
    .bind(name)
    .bind(platform(&req.device.platform))
    .bind(req.device.os_version.as_deref().map(|s| s.chars().take(64).collect::<String>()))
    .bind(req.device.app_version.as_deref().map(|s| s.chars().take(32).collect::<String>()))
    .bind(sqlx::types::ipnetwork::IpNetwork::from(client_ip(&headers, addr)))
    .bind(Utc::now() + LOGIN_TTL)
    .fetch_one(&state.db)
    .await?;

    let mut url = url::Url::parse("https://discord.com/oauth2/authorize").expect("valid");
    url.query_pairs_mut()
        .append_pair("client_id", &state.cfg.discord_client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &state.cfg.discord_redirect_uri())
        .append_pair("scope", "identify email")
        .append_pair("state", &state_token)
        .append_pair("prompt", "none");
    Ok(Json(StartResponse {
        login_id: id,
        authorize_url: url.to_string(),
        expires_in: LOGIN_TTL.num_seconds(),
        poll_interval_ms: 1500,
    }))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DiscordToken {
    access_token: String,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
    avatar: Option<String>,
    email: Option<String>,
    verified: Option<bool>,
}

pub async fn callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let ip = client_ip(&headers, addr);
    match handle_callback(&state, q, ip).await {
        Ok(name) => page(
            "You're signed in",
            &format!("Welcome, {}. You can close this tab and go back to Distanplay.", html_escape(&name)),
            true,
        ),
        Err(msg) => page("Couldn't sign you in", &html_escape(&msg), false),
    }
}

async fn handle_callback(state: &AppState, q: CallbackQuery, ip: std::net::IpAddr) -> Result<String, String> {
    let st = q.state.ok_or("The sign-in link is incomplete. Start again from the app.")?;
    #[derive(sqlx::FromRow)]
    struct Pending {
        id: Uuid,
        status: String,
        expires_at: chrono::DateTime<Utc>,
    }
    let pending: Option<Pending> = sqlx::query_as(
        "SELECT id, status::text AS status, expires_at FROM login_requests WHERE state_hash = $1",
    )
    .bind(sha256(&st))
    .fetch_optional(&state.db)
    .await
    .map_err(|e| e.to_string())?;
    let p = pending.ok_or("This sign-in link isn't valid any more. Start again from the app.")?;
    if p.status != "pending" || p.expires_at < Utc::now() {
        return Err("This sign-in link has already been used or expired. Start again from the app.".into());
    }
    let fail = |msg: String| {
        let db = state.db.clone();
        let id = p.id;
        async move {
            let _ = sqlx::query("UPDATE login_requests SET status = 'failed', error = $2 WHERE id = $1")
                .bind(id)
                .bind(&msg)
                .execute(&db)
                .await;
            msg
        }
    };
    if let Some(e) = q.error {
        return Err(fail(if e == "access_denied" { "Sign-in was canceled.".into() } else { format!("Discord said: {e}") }).await);
    }
    let code = match q.code {
        Some(c) => c,
        None => return Err(fail("Discord didn't send a code.".into()).await),
    };

    let profile = match discord_profile(state, &code).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("discord exchange failed: {e:#}");
            return Err(fail("Couldn't reach Discord. Try again in a moment.".into()).await);
        }
    };
    let user_id = match upsert_discord_user(state, &profile, ip).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("discord upsert failed: {e:#}");
            return Err(fail("Couldn't create your account. Try again.".into()).await);
        }
    };
    sqlx::query("UPDATE login_requests SET status = 'completed', user_id = $2, completed_at = now() WHERE id = $1 AND status = 'pending'")
        .bind(p.id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(profile.global_name.clone().unwrap_or(profile.username.clone()))
}

async fn discord_profile(state: &AppState, code: &str) -> anyhow::Result<DiscordUser> {
    let token: DiscordToken = state
        .http
        .post("https://discord.com/api/v10/oauth2/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &state.cfg.discord_redirect_uri()),
            ("client_id", &state.cfg.discord_client_id),
            ("client_secret", &state.cfg.discord_client_secret),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let user: DiscordUser = state
        .http
        .get("https://discord.com/api/v10/users/@me")
        .bearer_auth(&token.access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // We only needed the profile; drop Discord's token right away (best effort).
    let _ = state
        .http
        .post("https://discord.com/api/v10/oauth2/token/revoke")
        .form(&[
            ("token", token.access_token.as_str()),
            ("token_type_hint", "access_token"),
            ("client_id", &state.cfg.discord_client_id),
            ("client_secret", &state.cfg.discord_client_secret),
        ])
        .send()
        .await;
    Ok(user)
}

/// Finds the account linked to this Discord user, or creates one (taking their Discord
/// username when it's free here, otherwise the closest free variant).
async fn upsert_discord_user(state: &AppState, d: &DiscordUser, ip: std::net::IpAddr) -> anyhow::Result<Uuid> {
    let avatar = d.avatar.as_ref().map(|a| {
        let ext = if a.starts_with("a_") { "gif" } else { "png" };
        format!("https://cdn.discordapp.com/avatars/{}/{a}.{ext}?size=256", d.id)
    });
    let verified = d.verified.unwrap_or(false);
    let email = d.email.clone().filter(|_| verified);
    let display: String = d.global_name.clone().unwrap_or_else(|| d.username.clone()).chars().take(32).collect();

    let mut tx = state.db.begin().await?;
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM user_identities WHERE provider = 'discord' AND provider_user_id = $1")
            .bind(&d.id)
            .fetch_optional(&mut *tx)
            .await?;
    let user_id = match existing {
        Some(uid) => {
            sqlx::query(
                "UPDATE user_identities SET provider_username = $2, email = $3, email_verified = $4, avatar_url = $5, last_used_at = now()
                 WHERE provider = 'discord' AND provider_user_id = $1",
            )
            .bind(&d.id)
            .bind(&d.username)
            .bind(&d.email)
            .bind(verified)
            .bind(&avatar)
            .execute(&mut *tx)
            .await?;
            // Keep the avatar fresh; don't overwrite names the user changed here.
            sqlx::query("UPDATE users SET avatar_url = COALESCE($2, avatar_url), last_login_at = now() WHERE id = $1")
                .bind(uid)
                .bind(&avatar)
                .execute(&mut *tx)
                .await?;
            uid
        }
        None => {
            // An existing account with the same verified email gets Discord linked to it.
            let by_email: Option<Uuid> = match &email {
                Some(e) => sqlx::query_scalar("SELECT id FROM users WHERE email = $1 AND email_verified_at IS NOT NULL AND deleted_at IS NULL")
                    .bind(e)
                    .fetch_optional(&mut *tx)
                    .await?,
                None => None,
            };
            let uid = match by_email {
                Some(uid) => uid,
                None => {
                    let uname = username::free_variant(&mut tx, &d.username).await?;
                    let uid: Uuid = sqlx::query_scalar(
                        "INSERT INTO users (username, display_name, email, email_verified_at, avatar_url, last_login_at)
                         VALUES ($1, $2, $3, CASE WHEN $3::citext IS NULL THEN NULL ELSE now() END, $4, now()) RETURNING id",
                    )
                    .bind(&uname)
                    .bind(&display)
                    .bind(&email)
                    .bind(&avatar)
                    .fetch_one(&mut *tx)
                    .await?;
                    sqlx::query("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE is_default")
                        .bind(uid)
                        .execute(&mut *tx)
                        .await?;
                    audit(&mut *tx, Some(uid), "user.created", Some(("user", uid)), Some(ip), json!({ "provider": "discord" }))
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    uid
                }
            };
            sqlx::query(
                "INSERT INTO user_identities (user_id, provider, provider_user_id, provider_username, email, email_verified, avatar_url, last_used_at)
                 VALUES ($1, 'discord', $2, $3, $4, $5, $6, now())",
            )
            .bind(uid)
            .bind(&d.id)
            .bind(&d.username)
            .bind(&d.email)
            .bind(verified)
            .bind(&avatar)
            .execute(&mut *tx)
            .await?;
            uid
        }
    };
    tx.commit().await?;
    Ok(user_id)
}

#[derive(Deserialize)]
pub struct PollRequest {
    pub login_id: Uuid,
    pub poll_secret: String,
}

#[derive(Serialize)]
pub struct SignedIn {
    pub access_token: String,
    pub access_expires_at: chrono::DateTime<Utc>,
    pub refresh_token: String,
    pub device_id: Uuid,
    pub me: MeResponse,
}

/// 202 while the browser step is pending; 200 with tokens once; 410 when failed/expired.
pub async fn poll(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PollRequest>,
) -> ApiResult<Response> {
    let ip = client_ip(&headers, addr);
    state.limits.check("login_poll", ip, 120)?;
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let mut tx = state.db.begin().await?;
    #[derive(sqlx::FromRow)]
    struct Row {
        status: String,
        user_id: Option<Uuid>,
        error: Option<String>,
        expires_at: chrono::DateTime<Utc>,
        install_id: Uuid,
        device_name: String,
        platform: String,
        os_version: Option<String>,
        app_version: Option<String>,
    }
    let row: Option<Row> = sqlx::query_as(
        "SELECT status::text AS status, user_id, error, expires_at, install_id, device_name, platform::text AS platform, os_version, app_version
         FROM login_requests WHERE id = $1 AND poll_secret_hash = $2 FOR UPDATE",
    )
    .bind(req.login_id)
    .bind(sha256(&req.poll_secret))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(r) = row else { return Err(ApiError::NotFound) };
    match r.status.as_str() {
        "pending" if r.expires_at > Utc::now() => {
            return Ok((StatusCode::ACCEPTED, Json(json!({ "status": "pending" }))).into_response());
        }
        "completed" => {}
        "failed" => {
            let msg = r.error.unwrap_or_else(|| "Sign-in failed".into());
            return Ok((StatusCode::GONE, Json(json!({ "status": "failed", "message": msg }))).into_response());
        }
        _ => {
            return Ok((StatusCode::GONE, Json(json!({ "status": "expired", "message": "Sign-in expired. Try again." })))
                .into_response());
        }
    }
    let user_id = r.user_id.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("completed login without user")))?;
    sqlx::query("UPDATE login_requests SET status = 'consumed' WHERE id = $1").bind(req.login_id).execute(&mut *tx).await?;
    // The device: one per (account, install), renamed/updated on each sign-in.
    let device_id: Uuid = sqlx::query_scalar(
        "INSERT INTO devices (user_id, install_id, name, platform, os_version, app_version, last_seen_at, last_ip)
         VALUES ($1, $2, $3, $4::device_platform, $5, $6, now(), $7)
         ON CONFLICT (user_id, install_id) DO UPDATE SET
            name = EXCLUDED.name, platform = EXCLUDED.platform, os_version = EXCLUDED.os_version,
            app_version = EXCLUDED.app_version, last_seen_at = now(), last_ip = EXCLUDED.last_ip, revoked_at = NULL
         RETURNING id",
    )
    .bind(user_id)
    .bind(r.install_id)
    .bind(&r.device_name)
    .bind(&r.platform)
    .bind(&r.os_version)
    .bind(&r.app_version)
    .bind(sqlx::types::ipnetwork::IpNetwork::from(ip))
    .fetch_one(&mut *tx)
    .await?;
    audit(&mut *tx, Some(user_id), "auth.signed_in", Some(("device", device_id)), Some(ip), json!({ "method": "discord" })).await?;
    tx.commit().await?;

    let tokens = issue(&state, user_id, Some(device_id), "discord", Some(ip), ua).await?;
    let me = load_me(&state.db, user_id).await?;
    Ok(Json(SignedIn {
        access_token: tokens.access_token,
        access_expires_at: tokens.access_expires_at,
        refresh_token: tokens.refresh_token,
        device_id,
        me,
    })
    .into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The page the browser lands on after Discord.
fn page(title: &str, body: &str, ok: bool) -> Response {
    let (accent, icon) = if ok { ("#6A4BF5", "✓") } else { ("#FF5C6C", "!") };
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Distanplay</title>
<style>
:root{{color-scheme:dark}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0e12;color:#eceef4;
font:16px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}}
.card{{max-width:420px;margin:24px;padding:36px 32px;border:1px solid #2c2f3b;border-radius:16px;background:#181920;text-align:center}}
.icon{{width:56px;height:56px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center;font-size:28px;font-weight:700;
background:{accent}22;color:{accent}}}h1{{margin:0 0 8px;font-size:22px}}p{{margin:0;color:#8e93a6}}
</style></head><body><main class="card"><div class="icon">{icon}</div><h1>{title}</h1><p>{body}</p></main></body></html>"#
    ))
    .into_response()
}
