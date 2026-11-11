//! Sessions for a desktop app that stays signed in.
//!
//! - **Access token**: a JWT (HS256) valid for 15 minutes, sent as `Authorization:
//!   Bearer`. Cheap to check, short-lived so a leak is contained.
//! - **Refresh token**: 32 random bytes, stored by the app in the OS keychain (macOS
//!   Keychain / Windows Credential Manager) and only as a SHA-256 hash here. Every
//!   refresh rotates it; the expiry slides 90 days from last use, so an app that's used
//!   stays signed in indefinitely. Re-using a rotated token revokes the whole sign-in
//!   (theft detection), as recommended by the OAuth 2.0 Security BCP.
//! - Each request also checks that the sign-in (token family) hasn't been revoked and
//!   the account is active, so sign-out and suspensions apply immediately.

pub mod discord;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

pub const ACCESS_TTL: Duration = Duration::minutes(15);
pub const REFRESH_IDLE: Duration = Duration::days(90);

pub fn random_token(prefix: &str) -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

pub fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    /// Sign-in (refresh token family).
    sid: Uuid,
    did: Option<Uuid>,
    iat: i64,
    exp: i64,
    iss: String,
    typ: String,
}

pub struct Tokens {
    pub access_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_token: String,
}

fn sign_access(secret: &[u8], user_id: Uuid, family: Uuid, device: Option<Uuid>) -> ApiResult<(String, DateTime<Utc>)> {
    let now = Utc::now();
    let exp = now + ACCESS_TTL;
    let claims = Claims {
        sub: user_id,
        sid: family,
        did: device,
        iat: now.timestamp(),
        exp: exp.timestamp(),
        iss: "distanplay".into(),
        typ: "access".into(),
    };
    let t = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| ApiError::Internal(e.into()))?;
    Ok((t, exp))
}

/// Starts a new sign-in for `user_id` on `device_id`.
pub async fn issue(
    state: &AppState,
    user_id: Uuid,
    device_id: Option<Uuid>,
    method: &str,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> ApiResult<Tokens> {
    let family = Uuid::now_v7();
    let refresh = random_token("dpr_");
    sqlx::query(
        "INSERT INTO auth_sessions (family_id, user_id, device_id, refresh_token_hash, auth_method, ip, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5::auth_method, $6, $7, $8)",
    )
    .bind(family)
    .bind(user_id)
    .bind(device_id)
    .bind(sha256(&refresh))
    .bind(method)
    .bind(ip.map(sqlx::types::ipnetwork::IpNetwork::from))
    .bind(user_agent)
    .bind(Utc::now() + REFRESH_IDLE)
    .execute(&state.db)
    .await?;
    let (access_token, access_expires_at) = sign_access(&state.cfg.jwt_secret, user_id, family, device_id)?;
    Ok(Tokens { access_token, access_expires_at, refresh_token: refresh })
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    family_id: Uuid,
    user_id: Uuid,
    device_id: Option<Uuid>,
    auth_method: String,
    expires_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    user_status: String,
}

/// Rotates a refresh token. Reuse of an old token revokes the whole sign-in.
pub async fn refresh(state: &AppState, token: &str, ip: Option<std::net::IpAddr>, ua: Option<&str>) -> ApiResult<Tokens> {
    let mut tx = state.db.begin().await?;
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id, s.family_id, s.user_id, s.device_id, s.auth_method::text AS auth_method, s.expires_at,
                s.rotated_at, s.revoked_at, u.status::text AS user_status
         FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.refresh_token_hash = $1
         FOR UPDATE OF s",
    )
    .bind(sha256(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(s) = row else { return Err(ApiError::Unauthorized) };

    if s.rotated_at.is_some() && s.revoked_at.is_none() {
        // A token that was already exchanged is being used again: someone has a copy.
        sqlx::query("UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'refresh_reuse' WHERE family_id = $1 AND revoked_at IS NULL")
            .bind(s.family_id)
            .execute(&mut *tx)
            .await?;
        audit(&mut *tx, Some(s.user_id), "auth.refresh_reuse", Some(("session", s.family_id)), ip, serde_json::json!({})).await?;
        tx.commit().await?;
        tracing::warn!(user = %s.user_id, family = %s.family_id, "refresh token reuse: sign-in revoked");
        return Err(ApiError::Unauthorized);
    }
    if s.revoked_at.is_some() || s.expires_at < Utc::now() || s.user_status != "active" {
        return Err(ApiError::Unauthorized);
    }

    let new_refresh = random_token("dpr_");
    let new_id = Uuid::now_v7();
    sqlx::query("UPDATE auth_sessions SET rotated_at = now(), replaced_by = $2, last_used_at = now() WHERE id = $1")
        .bind(s.id)
        .bind(new_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO auth_sessions (id, family_id, user_id, device_id, refresh_token_hash, auth_method, ip, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6::auth_method, $7, $8, $9)",
    )
    .bind(new_id)
    .bind(s.family_id)
    .bind(s.user_id)
    .bind(s.device_id)
    .bind(sha256(&new_refresh))
    .bind(&s.auth_method)
    .bind(ip.map(sqlx::types::ipnetwork::IpNetwork::from))
    .bind(ua)
    .bind(Utc::now() + REFRESH_IDLE)
    .execute(&mut *tx)
    .await?;
    if let Some(d) = s.device_id {
        sqlx::query("UPDATE devices SET last_seen_at = now(), last_ip = $2 WHERE id = $1")
            .bind(d)
            .bind(ip.map(sqlx::types::ipnetwork::IpNetwork::from))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let (access_token, access_expires_at) = sign_access(&state.cfg.jwt_secret, s.user_id, s.family_id, s.device_id)?;
    Ok(Tokens { access_token, access_expires_at, refresh_token: new_refresh })
}

pub async fn revoke_family(db: &PgPool, family: Uuid, reason: &str) -> ApiResult<()> {
    sqlx::query("UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2 WHERE family_id = $1 AND revoked_at IS NULL")
        .bind(family)
        .bind(reason)
        .execute(db)
        .await?;
    Ok(())
}

/// The signed-in caller, extracted from `Authorization: Bearer <access token>`.
#[derive(Clone, Copy, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub device_id: Option<Uuid>,
}

impl AuthUser {
    pub async fn from_token(state: &AppState, token: &str) -> ApiResult<Self> {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&["distanplay"]);
        v.leeway = 30;
        let data = jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(&state.cfg.jwt_secret), &v)
            .map_err(|_| ApiError::Unauthorized)?;
        let c = data.claims;
        if c.typ != "access" {
            return Err(ApiError::Unauthorized);
        }
        // Sign-out and suspensions apply at once, not when the token expires.
        let ok: Option<bool> = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM auth_sessions WHERE family_id = $1 AND revoked_at IS NULL)
                    AND (SELECT status = 'active' FROM users WHERE id = $2)",
        )
        .bind(c.sid)
        .bind(c.sub)
        .fetch_one(&state.db)
        .await?;
        if ok != Some(true) {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self { user_id: c.sub, family_id: c.sid, device_id: c.did })
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
        let token = header.and_then(|h| h.strip_prefix("Bearer ")).ok_or(ApiError::Unauthorized)?;
        AuthUser::from_token(state, token.trim()).await
    }
}

/// Requires an admin permission ("users.suspend", …) from roles or user overrides.
pub async fn require_permission(db: &PgPool, user: &AuthUser, key: &str) -> ApiResult<()> {
    let allowed: Option<bool> = sqlx::query_scalar(
        "SELECT CASE
            WHEN EXISTS (SELECT 1 FROM user_permissions up JOIN permissions p ON p.id = up.permission_id
                         WHERE up.user_id = $1 AND p.key = $2 AND up.effect = 'deny') THEN false
            WHEN EXISTS (SELECT 1 FROM user_permissions up JOIN permissions p ON p.id = up.permission_id
                         WHERE up.user_id = $1 AND p.key = $2 AND up.effect = 'allow') THEN true
            ELSE EXISTS (SELECT 1 FROM user_roles ur
                         JOIN role_permissions rp ON rp.role_id = ur.role_id
                         JOIN permissions p ON p.id = rp.permission_id
                         WHERE ur.user_id = $1 AND p.key = $2)
         END",
    )
    .bind(user.user_id)
    .bind(key)
    .fetch_one(db)
    .await?;
    if allowed == Some(true) { Ok(()) } else { Err(ApiError::Forbidden(format!("missing permission {key}"))) }
}

pub async fn audit<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
    actor: Option<Uuid>,
    action: &str,
    target: Option<(&str, Uuid)>,
    ip: Option<std::net::IpAddr>,
    metadata: serde_json::Value,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO audit_log (actor_user_id, action, target_type, target_id, ip, metadata) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(actor)
        .bind(action)
        .bind(target.map(|t| t.0))
        .bind(target.map(|t| t.1))
        .bind(ip.map(sqlx::types::ipnetwork::IpNetwork::from))
        .bind(metadata)
        .execute(db)
        .await?;
    Ok(())
}

// ───────────────────────────── connection tickets ─────────────────────────────

/// What the server vouches for when a friend may connect: signed with Ed25519 so the
/// host app can check it offline with the server's public key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TicketClaims {
    pub session_id: Uuid,
    pub host_device_id: Uuid,
    pub viewer_user_id: Uuid,
    pub viewer_device_id: Option<Uuid>,
    pub viewer_name: String,
    pub control_input: bool,
    pub hear_audio: bool,
    pub use_clipboard: bool,
    pub exp: i64,
}

pub fn sign_ticket(key: &ed25519_dalek::SigningKey, claims: &TicketClaims) -> String {
    use ed25519_dalek::Signer;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = serde_json::to_vec(claims).expect("serializable");
    let sig = key.sign(&payload);
    format!("{}.{}", b64.encode(payload), b64.encode(sig.to_bytes()))
}
