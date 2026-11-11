//! First admin endpoints (for the future web admin). Every route checks a permission
//! from the roles system, so access is managed in the database, not in code.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AuthUser, audit, require_permission};
use crate::error::{ApiError, ApiResult, bad};

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    limit: Option<i64>,
    before: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AdminUser {
    id: Uuid,
    username: String,
    display_name: String,
    email: Option<String>,
    status: String,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
    roles: Vec<String>,
}

pub async fn users(State(state): State<AppState>, user: AuthUser, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<AdminUser>>> {
    require_permission(&state.db, &user, "users.read").await?;
    let like = q.q.as_deref().map(|s| format!("%{}%", s.trim()));
    Ok(Json(
        sqlx::query_as(
            "SELECT u.id, u.username::text AS username, u.display_name, u.email::text AS email, u.status::text AS status,
                    u.created_at, u.last_seen_at,
                    COALESCE(ARRAY(SELECT r.key FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id), '{}') AS roles
             FROM users u
             WHERE ($1::text IS NULL OR u.username::text ILIKE $1 OR u.display_name ILIKE $1 OR u.email::text ILIKE $1)
               AND ($2::timestamptz IS NULL OR u.created_at < $2)
             ORDER BY u.created_at DESC LIMIT $3",
        )
        .bind(like)
        .bind(q.before)
        .bind(q.limit.unwrap_or(50).clamp(1, 200))
        .fetch_all(&state.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct SetStatus {
    status: String,
    reason: Option<String>,
}

/// Suspends or restores an account. Suspending also signs it out everywhere.
pub async fn set_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<SetStatus>,
) -> ApiResult<Json<serde_json::Value>> {
    require_permission(&state.db, &user, "users.suspend").await?;
    if !matches!(req.status.as_str(), "active" | "suspended") {
        return Err(bad("invalid_status", "status must be active or suspended"));
    }
    if id == user.user_id {
        return Err(bad("self", "You can't change your own status"));
    }
    let mut tx = state.db.begin().await?;
    let n = sqlx::query("UPDATE users SET status = $2::user_status, status_reason = $3 WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .bind(&req.status)
        .bind(&req.reason)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    if req.status == "suspended" {
        sqlx::query("UPDATE auth_sessions SET revoked_at = now(), revoke_reason = 'suspended' WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    audit(&mut *tx, Some(user.user_id), "admin.user_status", Some(("user", id)), None, json!({ "status": req.status, "reason": req.reason }))
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct RoleChange {
    role: String,
}

pub async fn grant_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<RoleChange>,
) -> ApiResult<Json<serde_json::Value>> {
    require_permission(&state.db, &user, "roles.manage").await?;
    let n = sqlx::query("INSERT INTO user_roles (user_id, role_id, granted_by) SELECT $1, id, $3 FROM roles WHERE key = $2 ON CONFLICT DO NOTHING")
        .bind(id)
        .bind(&req.role)
        .bind(user.user_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    audit(&state.db, Some(user.user_id), "admin.role_granted", Some(("user", id)), None, json!({ "role": req.role })).await?;
    Ok(Json(json!({ "ok": true, "granted": n > 0 })))
}

pub async fn revoke_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, role)): Path<(Uuid, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_permission(&state.db, &user, "roles.manage").await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE key = $2)")
        .bind(id)
        .bind(&role)
        .execute(&state.db)
        .await?;
    audit(&state.db, Some(user.user_id), "admin.role_revoked", Some(("user", id)), None, json!({ "role": role })).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn live(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<serde_json::Value>> {
    require_permission(&state.db, &user, "relays.read").await?;
    Ok(Json(state.hub.stats()))
}
