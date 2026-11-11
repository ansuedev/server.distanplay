//! The signed-in user: profile, devices and sign-ins.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{AuthUser, audit, revoke_family};
use crate::error::{ApiError, ApiResult, bad};
use crate::{AppState, username};

#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct PublicUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

pub async fn load_me(db: &PgPool, user_id: Uuid) -> ApiResult<MeResponse> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        username: String,
        display_name: String,
        email: Option<String>,
        avatar_url: Option<String>,
        created_at: DateTime<Utc>,
    }
    let u: Row = sqlx::query_as(
        "SELECT id, username::text AS username, display_name, email::text AS email, avatar_url, created_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let roles: Vec<String> =
        sqlx::query_scalar("SELECT r.key FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.key")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.key FROM permissions p
         WHERE (p.id IN (SELECT rp.permission_id FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id WHERE ur.user_id = $1)
                OR p.id IN (SELECT permission_id FROM user_permissions WHERE user_id = $1 AND effect = 'allow'))
           AND p.id NOT IN (SELECT permission_id FROM user_permissions WHERE user_id = $1 AND effect = 'deny')
         ORDER BY p.key",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(MeResponse {
        id: u.id,
        username: u.username,
        display_name: u.display_name,
        email: u.email,
        avatar_url: u.avatar_url,
        created_at: u.created_at,
        roles,
        permissions,
    })
}

pub async fn me(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<MeResponse>> {
    Ok(Json(load_me(&state.db, user.user_id).await?))
}

#[derive(Deserialize)]
pub struct UpdateMe {
    pub username: Option<String>,
    pub display_name: Option<String>,
}

pub async fn update_me(State(state): State<AppState>, user: AuthUser, Json(req): Json<UpdateMe>) -> ApiResult<Json<MeResponse>> {
    if let Some(u) = &req.username {
        let u = u.trim().to_lowercase();
        if !username::is_valid(&u) {
            return Err(bad(
                "invalid_username",
                "Usernames are 2–32 characters: lowercase letters, numbers, _ and . (no two dots in a row)",
            ));
        }
        let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1 AND id <> $2)")
            .bind(&u)
            .bind(user.user_id)
            .fetch_one(&state.db)
            .await?;
        if taken {
            return Err(ApiError::Conflict("username_taken", "That username is taken".into()));
        }
        sqlx::query("UPDATE users SET username = $2 WHERE id = $1").bind(user.user_id).bind(&u).execute(&state.db).await?;
    }
    if let Some(d) = &req.display_name {
        let d = d.trim();
        if d.is_empty() || d.chars().count() > 32 {
            return Err(bad("invalid_display_name", "Profile names are 1–32 characters"));
        }
        sqlx::query("UPDATE users SET display_name = $2 WHERE id = $1").bind(user.user_id).bind(d).execute(&state.db).await?;
    }
    Ok(Json(load_me(&state.db, user.user_id).await?))
}

// ───────────────────────────── devices ─────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceOut {
    pub id: Uuid,
    pub name: String,
    pub platform: String,
    pub app_version: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    pub online: bool,
    #[sqlx(skip)]
    pub this_device: bool,
}

pub async fn devices(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<DeviceOut>>> {
    let mut list: Vec<DeviceOut> = sqlx::query_as(
        "SELECT id, name, platform::text AS platform, app_version, last_seen_at FROM devices
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY last_seen_at DESC NULLS LAST",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    for d in &mut list {
        d.online = state.hub.is_online(d.id);
        d.this_device = Some(d.id) == user.device_id;
    }
    Ok(Json(list))
}

#[derive(Deserialize)]
pub struct RenameDevice {
    pub name: String,
}

pub async fn rename_device(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<RenameDevice>,
) -> ApiResult<Json<serde_json::Value>> {
    let name: String = req.name.trim().chars().take(64).collect();
    if name.is_empty() {
        return Err(bad("invalid_name", "Device name can't be empty"));
    }
    let n = sqlx::query("UPDATE devices SET name = $3 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL")
        .bind(id)
        .bind(user.user_id)
        .bind(&name)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Removes a device: signs it out and stops friends from connecting to it.
pub async fn remove_device(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    let n = sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL")
        .bind(id)
        .bind(user.user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query("UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'device_removed' WHERE device_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(&mut *tx, Some(user.user_id), "device.removed", Some(("device", id)), None, serde_json::json!({})).await?;
    tx.commit().await?;
    state.hub.kick_device(id);
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ───────────────────────────── sign-ins ─────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct SessionOut {
    pub family_id: Uuid,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub auth_method: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    #[sqlx(skip)]
    pub current: bool,
}

pub async fn sessions(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<SessionOut>>> {
    let mut list: Vec<SessionOut> = sqlx::query_as(
        "SELECT DISTINCT ON (s.family_id) s.family_id, s.device_id, d.name AS device_name, s.auth_method::text AS auth_method,
                MIN(s.created_at) OVER (PARTITION BY s.family_id) AS created_at, s.last_used_at
         FROM auth_sessions s LEFT JOIN devices d ON d.id = s.device_id
         WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.rotated_at IS NULL AND s.expires_at > now()
         ORDER BY s.family_id, s.last_used_at DESC",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    for s in &mut list {
        s.current = s.family_id == user.family_id;
    }
    Ok(Json(list))
}

pub async fn revoke_session(State(state): State<AppState>, user: AuthUser, Path(family): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let owned: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM auth_sessions WHERE family_id = $1 AND user_id = $2)")
        .bind(family)
        .bind(user.user_id)
        .fetch_one(&state.db)
        .await?;
    if !owned {
        return Err(ApiError::NotFound);
    }
    revoke_family(&state.db, family, "user_revoked").await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Exact-username lookup (like Discord's "Add Friend").
pub async fn find_user(
    State(state): State<AppState>,
    _user: AuthUser,
    Path(name): Path<String>,
) -> ApiResult<Json<PublicUser>> {
    let u: Option<PublicUser> = sqlx::query_as(
        "SELECT id, username::text AS username, display_name, avatar_url FROM users WHERE username = $1 AND status = 'active'",
    )
    .bind(name.trim().trim_start_matches('@').to_lowercase())
    .fetch_optional(&state.db)
    .await?;
    u.map(Json).ok_or(ApiError::NotFound)
}
