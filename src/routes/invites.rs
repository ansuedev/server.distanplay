//! Invites: links that let someone join a host's PC (`<PUBLIC_URL>/j/<token>`).
//!
//! * **Named** (`for_discord_id` set, from `/jugar @friend`): only that Discord account
//!   can use it, once, and it connects without a prompt (the host chose them).
//! * **Open** (from `/jugar` with nobody named, or the "Join" button on the host's
//!   Discord profile): anyone signed in, a few times, and the host approves each one.
//!
//! The link opens a page that launches the app (`distanplay://join/<token>`) or offers
//! the download; the app redeems the token over the hub (`connect_invite`). Tokens are
//! 128-bit random and stored only as a SHA-256 hash.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult, bad};
use crate::{AppState, client_ip};

/// How an invite came to be (stored as text).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Discord,
    Presence,
    App,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Discord => "discord",
            Source::Presence => "presence",
            Source::App => "app",
        }
    }
}

pub fn new_token() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.trim().as_bytes()).to_vec()
}

/// Tokens are 22 url-safe base64 characters.
pub fn plausible_token(t: &str) -> bool {
    t.len() == 22 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn url(state: &AppState, token: &str) -> String {
    format!("{}/j/{token}", state.cfg.public_url)
}

pub struct NewInvite<'a> {
    pub host_user: Uuid,
    pub host_device: Uuid,
    /// (Discord id, display name) of the one person it's for.
    pub for_discord: Option<(&'a str, &'a str)>,
    pub source: Source,
    pub max_uses: i32,
    pub ttl_secs: i64,
}

/// Creates an invite; returns (id, token).
pub async fn create(state: &AppState, n: NewInvite<'_>) -> ApiResult<(Uuid, String)> {
    let token = new_token();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO invites (token_hash, host_user_id, host_device_id, for_discord_id, for_name, source, max_uses, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8::bigint)) RETURNING id",
    )
    .bind(token_hash(&token))
    .bind(n.host_user)
    .bind(n.host_device)
    .bind(n.for_discord.map(|f| f.0))
    .bind(n.for_discord.map(|f| f.1.chars().take(100).collect::<String>()))
    .bind(n.source.as_str())
    .bind(n.max_uses.max(1))
    .bind(n.ttl_secs.max(60))
    .fetch_one(&state.db)
    .await?;
    Ok((id, token))
}

#[derive(sqlx::FromRow, Clone)]
struct Row {
    id: Uuid,
    host_user_id: Uuid,
    host_device_id: Uuid,
    for_discord_id: Option<String>,
    for_name: Option<String>,
    max_uses: i32,
    uses: i32,
    expired: bool,
    revoked: bool,
    host_name: String,
    host_username: String,
    host_avatar: Option<String>,
    device_name: Option<String>,
    device_gone: bool,
}

async fn load(state: &AppState, token: &str) -> ApiResult<Option<Row>> {
    if !plausible_token(token) {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT i.id, i.host_user_id, i.host_device_id, i.for_discord_id, i.for_name, i.max_uses, i.uses,
                i.expires_at < now() AS expired, i.revoked_at IS NOT NULL AS revoked,
                u.display_name AS host_name, u.username::text AS host_username, u.avatar_url AS host_avatar,
                d.name AS device_name, (d.revoked_at IS NOT NULL OR u.status <> 'active') AS device_gone
         FROM invites i JOIN users u ON u.id = i.host_user_id JOIN devices d ON d.id = i.host_device_id
         WHERE i.token_hash = $1",
    )
    .bind(token_hash(token))
    .fetch_optional(&state.db)
    .await?)
}

/// Why an invite can't be used right now (`None`: it can).
fn unusable(r: &Row) -> Option<&'static str> {
    if r.revoked || r.device_gone {
        Some("revoked")
    } else if r.expired {
        Some("expired")
    } else if r.uses >= r.max_uses {
        Some("used")
    } else {
        None
    }
}

/// An invite someone is allowed to use.
pub struct Redeemed {
    pub host_user: Uuid,
    pub host_device: Uuid,
    /// Named invite: connect without asking the host.
    pub auto: bool,
}

/// Checks an invite for `viewer` and, if it can be used, counts the use. The reason
/// on failure is sent to the app as-is (`not_found`, `expired`, `used`, `revoked`,
/// `not_for_you`, `self`, `offline`).
pub async fn redeem(state: &AppState, token: &str, viewer: Uuid, viewer_device: Uuid) -> ApiResult<Result<Redeemed, &'static str>> {
    let Some(r) = load(state, token).await? else { return Ok(Err("not_found")) };
    if let Some(why) = unusable(&r) {
        return Ok(Err(why));
    }
    if r.host_device_id == viewer_device {
        return Ok(Err("self"));
    }
    if let Some(want) = &r.for_discord_id {
        let mine: Option<String> =
            sqlx::query_scalar("SELECT provider_user_id FROM user_identities WHERE provider = 'discord' AND user_id = $1 AND provider_user_id = $2")
                .bind(viewer)
                .bind(want)
                .fetch_optional(&state.db)
                .await?;
        if mine.is_none() {
            return Ok(Err("not_for_you"));
        }
    }
    if !state.hub.is_online(r.host_device_id) {
        return Ok(Err("offline"));
    }
    // Count the use (atomically: two people racing for the last use can't both win).
    let counted = sqlx::query("UPDATE invites SET uses = uses + 1 WHERE id = $1 AND uses < max_uses AND revoked_at IS NULL AND expires_at > now()")
        .bind(r.id)
        .execute(&state.db)
        .await?
        .rows_affected()
        == 1;
    if !counted {
        return Ok(Err("used"));
    }
    let own = r.host_user_id == viewer;
    Ok(Ok(Redeemed { host_user: r.host_user_id, host_device: r.host_device_id, auto: own || r.for_discord_id.is_some() }))
}

// ───────────────────────────── API ─────────────────────────────

#[derive(Deserialize)]
pub struct CreateBody {
    /// Lifetime, 5 minutes to 24 hours (default 2 hours).
    pub ttl_secs: Option<i64>,
    /// 1 to 50 uses (default 8).
    pub max_uses: Option<i32>,
    /// "presence" (default: replaces this device's previous one) or "app".
    pub source: Option<String>,
}

/// `POST /v1/invites` — an open invite to the calling device (the host approves each use).
pub async fn create_route(State(state): State<AppState>, user: AuthUser, Json(b): Json<CreateBody>) -> ApiResult<Json<serde_json::Value>> {
    let device = user.device_id.ok_or_else(|| bad("no_device", "This sign-in has no device"))?;
    let source = match b.source.as_deref() {
        Some("app") => Source::App,
        _ => Source::Presence,
    };
    if source == Source::Presence {
        // One profile link per device at a time.
        sqlx::query("UPDATE invites SET revoked_at = now() WHERE host_device_id = $1 AND source = 'presence' AND revoked_at IS NULL")
            .bind(device)
            .execute(&state.db)
            .await?;
    }
    let ttl = b.ttl_secs.unwrap_or(2 * 3600).clamp(300, 24 * 3600);
    let n = NewInvite {
        host_user: user.user_id,
        host_device: device,
        for_discord: None,
        source,
        max_uses: b.max_uses.unwrap_or(8).clamp(1, 50),
        ttl_secs: ttl,
    };
    let (id, token) = create(&state, n).await?;
    Ok(Json(json!({ "id": id, "token": token, "url": url(&state, &token), "expires_in": ttl })))
}

/// `DELETE /v1/invites/{id}` — stops one of your invites working.
pub async fn revoke_route(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let n = sqlx::query("UPDATE invites SET revoked_at = now() WHERE id = $1 AND host_user_id = $2 AND revoked_at IS NULL")
        .bind(id)
        .bind(user.user_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "ok": true })))
}

/// `GET /v1/invites/{token}` — who it's from, for the app's "Join …?" prompt.
pub async fn preview_route(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state.limits.check("invite_preview", client_ip(&headers, addr), 60)?;
    let r = load(&state, &token).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "host": { "id": r.host_user_id, "display_name": r.host_name, "username": r.host_username, "avatar_url": r.host_avatar },
        "device": { "id": r.host_device_id, "name": r.device_name, "online": state.hub.is_online(r.host_device_id) },
        "for_name": r.for_name,
        "needs_approval": r.for_discord_id.is_none(),
        "problem": unusable(&r),
    })))
}

// ───────────────────────────── the page ─────────────────────────────

pub fn spanish(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("es"))
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// `GET /j/{token}` — opens the app, or explains how to get it.
pub async fn page_route(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let es = spanish(&headers);
    if state.limits.check("invite_page", client_ip(&headers, addr), 120).is_err() {
        return page(&state, es, None, "", Some(if es { "Demasiados intentos. Espera un minuto." } else { "Too many tries. Wait a minute." }));
    }
    let row = load(&state, &token).await.ok().flatten();
    let problem = match &row {
        None => Some(if es { "Esta invitación no existe." } else { "This invite doesn't exist." }),
        Some(r) => unusable(r).map(|why| match (why, es) {
            ("expired", true) => "Esta invitación ya caducó. Pide una nueva.",
            ("expired", false) => "This invite has expired. Ask for a new one.",
            ("used", true) => "Esta invitación ya se usó. Pide una nueva.",
            ("used", false) => "This invite has already been used. Ask for a new one.",
            (_, true) => "Esta invitación ya no es válida.",
            (_, false) => "This invite is no longer valid.",
        }),
    };
    page(&state, es, row.as_ref(), &token, problem)
}

fn page(state: &AppState, es: bool, r: Option<&Row>, token: &str, problem: Option<&str>) -> Response {
    let t = |a: &'static str, b: &'static str| if es { a } else { b };
    let host = r.map(|r| esc(&r.host_name)).unwrap_or_else(|| "Distanplay".into());
    let title = match r {
        Some(_) if problem.is_none() => format!("{host} {}", t("te invita a jugar", "invited you to play")),
        _ => t("Invitación de Distanplay", "Distanplay invite").to_string(),
    };
    let link = url(state, token);
    let deep = format!("distanplay://join/{token}");
    let download = state.cfg.download_url.as_deref().map(esc);
    let avatar = r
        .and_then(|r| r.host_avatar.as_deref())
        .map(|a| format!(r#"<img class="avatar" src="{}" alt="">"#, esc(a)))
        .unwrap_or_else(|| r#"<img class="avatar" src="/brand/icon.png" alt="">"#.into());
    let body = match (r, problem) {
        (_, Some(p)) => format!(r#"<p class="sub">{}</p>"#, esc(p)),
        (Some(r), None) => {
            let who = r.for_name.as_deref().map(esc);
            let detail = match (&who, es) {
                (Some(w), true) => format!("Invitación para <b>{w}</b>. Entras directo, sin esperar."),
                (Some(w), false) => format!("Invite for <b>{w}</b>. You'll go straight in."),
                (None, true) => format!("{host} acepta tu entrada desde su PC."),
                (None, false) => format!("{host} lets you in from their PC."),
            };
            let dl = download
                .as_ref()
                .map(|d| format!(r#"<a class="btn ghost" href="{d}">{}</a>"#, t("Descargar Distanplay", "Download Distanplay")))
                .unwrap_or_default();
            format!(
                r#"<p class="sub">{detail}</p>
<a class="btn" id="open" href="{deep}">{open}</a>{dl}
<div class="help"><p>{help}</p><div class="copy"><input readonly value="{link}" onclick="this.select()"><button onclick="navigator.clipboard.writeText('{link}');this.textContent='{copied}'">{copy}</button></div></div>
<script>setTimeout(function(){{location.href="{deep}"}},400)</script>"#,
                open = t("Abrir en Distanplay", "Open in Distanplay"),
                help = t(
                    "¿No se abre? Instala Distanplay e inicia sesión con Discord, o pega este enlace en <b>Conectar con un amigo</b>:",
                    "Didn't open? Install Distanplay and sign in with Discord, or paste this link into <b>Connect to a friend</b>:"
                ),
                copy = t("Copiar", "Copy"),
                copied = t("Copiado", "Copied"),
            )
        }
        (None, None) => String::new(),
    };
    let desc = match (r, problem) {
        (Some(_), None) => t("Únete y juega en su PC con Distanplay.", "Join and play on their PC with Distanplay."),
        _ => t("Juega en la PC de tus amigos.", "Play on your friends' PCs."),
    };
    let html = format!(
        r##"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Distanplay</title>
<meta property="og:title" content="{title}"><meta property="og:description" content="{desc}">
<meta property="og:site_name" content="Distanplay"><meta property="og:image" content="{public}/brand/icon.png">
<meta name="theme-color" content="#6A4BF5"><meta name="robots" content="noindex">
<link rel="icon" href="/brand/icon.png">
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d0e12;color:#eceef4;
font:16px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}}
.card{{width:100%;max-width:440px;padding:36px 28px;border:1px solid #2c2f3b;border-radius:16px;background:#181920;text-align:center}}
.avatar{{width:72px;height:72px;border-radius:50%;margin:0 auto 16px;display:block;background:#1f212a}}
h1{{margin:0 0 6px;font-size:22px}}.sub{{margin:0 0 22px;color:#8e93a6}}
.btn{{display:block;padding:13px 16px;border-radius:10px;background:#6A4BF5;color:#fff;text-decoration:none;font-weight:600;margin-top:10px}}
.btn.ghost{{background:transparent;border:1px solid #2c2f3b;color:#eceef4}}
.help{{margin-top:22px;font-size:13px;color:#8e93a6}}.help p{{margin:0 0 8px}}
.copy{{display:flex;gap:6px}}.copy input{{flex:1;min-width:0;background:#0d0e12;color:#eceef4;border:1px solid #2c2f3b;border-radius:8px;padding:8px;font:12px ui-monospace,monospace}}
.copy button{{background:#27293a;color:#eceef4;border:0;border-radius:8px;padding:0 12px;cursor:pointer}}
</style></head><body><main class="card">{avatar}<h1>{title}</h1>{body}</main></body></html>"##,
        lang = if es { "es" } else { "en" },
        public = state.cfg.public_url,
    );
    ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

/// `GET /brand/icon.png`
pub async fn icon() -> Response {
    const PNG: &[u8] = include_bytes!("../static/icon.png");
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "public, max-age=86400")], PNG).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let a = new_token();
        assert!(plausible_token(&a), "{a}");
        assert_ne!(a, new_token());
        assert_eq!(token_hash(&a), token_hash(&format!(" {a} ")));
        assert!(!plausible_token("short"));
        assert!(!plausible_token("aaaaaaaaaaaaaaaaaaaaa/"));
        assert_eq!(esc(r#"<a href="x">'"#), "&lt;a href=&quot;x&quot;&gt;&#39;");
    }
}
