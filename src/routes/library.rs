//! Recent connections and favorites, synced across your devices. A target is either a
//! friend's device or a raw code / address (a host without an account).

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::AppState;
use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult, bad};

#[derive(Deserialize)]
pub struct TargetIn {
    pub target_device_id: Option<Uuid>,
    pub target_address: Option<String>,
    pub label: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Entry {
    pub id: Uuid,
    pub target_device_id: Option<Uuid>,
    pub target_address: Option<String>,
    pub label: String,
    /// For device targets: the owner's profile name and the device's name.
    pub owner_display_name: Option<String>,
    pub owner_username: Option<String>,
    pub device_name: Option<String>,
    pub at: DateTime<Utc>,
    #[sqlx(default)]
    pub connect_count: Option<i32>,
    #[sqlx(skip)]
    pub online: Option<bool>,
}

/// Validates a target and that a device target belongs to a friend (or to you).
async fn check_target(state: &AppState, user: &AuthUser, t: &TargetIn) -> ApiResult<(Option<Uuid>, Option<String>, String)> {
    let label: String = t.label.trim().chars().take(64).collect();
    if label.is_empty() {
        return Err(bad("invalid_label", "label is required"));
    }
    match (t.target_device_id, t.target_address.as_deref().map(str::trim).filter(|a| !a.is_empty())) {
        (Some(d), None) => {
            let owner: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM devices WHERE id = $1 AND revoked_at IS NULL")
                .bind(d)
                .fetch_optional(&state.db)
                .await?;
            let owner = owner.ok_or(ApiError::NotFound)?;
            if owner != user.user_id && !super::friends::are_friends(&state.db, user.user_id, owner).await? {
                return Err(ApiError::Forbidden("You can only save your friends' devices".into()));
            }
            Ok((Some(d), None, label))
        }
        (None, Some(a)) if a.len() <= 255 => Ok((None, Some(a.to_string()), label)),
        _ => Err(bad("invalid_target", "Give exactly one of target_device_id or target_address")),
    }
}

fn annotate(state: &AppState, list: &mut [Entry]) {
    for e in list {
        e.online = e.target_device_id.map(|d| state.hub.is_present(d));
    }
}

pub async fn recents(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<Entry>>> {
    let mut list: Vec<Entry> = sqlx::query_as(
        "SELECT r.id, r.target_device_id, r.target_address, r.label, u.display_name AS owner_display_name,
                u.username::text AS owner_username, d.name AS device_name, r.last_connected_at AS at, r.connect_count
         FROM recent_connections r
         LEFT JOIN devices d ON d.id = r.target_device_id AND d.revoked_at IS NULL
         LEFT JOIN users u ON u.id = d.user_id
         WHERE r.user_id = $1 AND (r.target_device_id IS NULL OR d.id IS NOT NULL)
         ORDER BY r.last_connected_at DESC LIMIT 50",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    annotate(&state, &mut list);
    Ok(Json(list))
}

/// Records a connection (called by the app after it connects).
pub async fn touch_recent(State(state): State<AppState>, user: AuthUser, Json(t): Json<TargetIn>) -> ApiResult<Json<serde_json::Value>> {
    let (device, address, label) = check_target(&state, &user, &t).await?;
    if let Some(d) = device {
        sqlx::query(
            "INSERT INTO recent_connections (user_id, target_device_id, label) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, target_device_id) WHERE target_device_id IS NOT NULL DO UPDATE
             SET label = EXCLUDED.label, connect_count = recent_connections.connect_count + 1, last_connected_at = now()",
        )
        .bind(user.user_id)
        .bind(d)
        .bind(&label)
        .execute(&state.db)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO recent_connections (user_id, target_address, label) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, target_address) WHERE target_address IS NOT NULL DO UPDATE
             SET label = EXCLUDED.label, connect_count = recent_connections.connect_count + 1, last_connected_at = now()",
        )
        .bind(user.user_id)
        .bind(address)
        .bind(&label)
        .execute(&state.db)
        .await?;
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_recent(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM recent_connections WHERE id = $1 AND user_id = $2").bind(id).bind(user.user_id).execute(&state.db).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn favorites(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<Entry>>> {
    let mut list: Vec<Entry> = sqlx::query_as(
        "SELECT f.id, f.target_device_id, f.target_address, f.label, u.display_name AS owner_display_name,
                u.username::text AS owner_username, d.name AS device_name, f.created_at AS at, NULL::int AS connect_count
         FROM favorites f
         LEFT JOIN devices d ON d.id = f.target_device_id AND d.revoked_at IS NULL
         LEFT JOIN users u ON u.id = d.user_id
         WHERE f.user_id = $1 AND (f.target_device_id IS NULL OR d.id IS NOT NULL)
         ORDER BY f.position, f.created_at",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;
    annotate(&state, &mut list);
    Ok(Json(list))
}

pub async fn add_favorite(State(state): State<AppState>, user: AuthUser, Json(t): Json<TargetIn>) -> ApiResult<Json<serde_json::Value>> {
    let (device, address, label) = check_target(&state, &user, &t).await?;
    let next: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(position), -1) + 1 FROM favorites WHERE user_id = $1")
        .bind(user.user_id)
        .fetch_one(&state.db)
        .await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO favorites (user_id, target_device_id, target_address, label, position) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(user.user_id)
    .bind(device)
    .bind(address)
    .bind(&label)
    .bind(next)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(json!({ "ok": true, "id": id })))
}

pub async fn remove_favorite(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM favorites WHERE id = $1 AND user_id = $2").bind(id).bind(user.user_id).execute(&state.db).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct Order {
    pub ids: Vec<Uuid>,
}

/// Reorders favorites (ids in the new order).
pub async fn reorder_favorites(State(state): State<AppState>, user: AuthUser, Json(o): Json<Order>) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    for (i, id) in o.ids.iter().enumerate() {
        sqlx::query("UPDATE favorites SET position = $3 WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user.user_id)
            .bind(i as i32)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HistoryEntry {
    pub id: Uuid,
    pub role: String,
    pub other_display_name: String,
    pub other_username: String,
    pub device_name: Option<String>,
    pub route: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Your stream history (as viewer and as host).
pub async fn history(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<HistoryEntry>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT s.id,
                    CASE WHEN s.viewer_user_id = $1 THEN 'viewer' ELSE 'host' END AS role,
                    o.display_name AS other_display_name, o.username::text AS other_username,
                    d.name AS device_name, s.route::text AS route, s.started_at, s.ended_at
             FROM connection_sessions s
             JOIN users o ON o.id = CASE WHEN s.viewer_user_id = $1 THEN s.host_user_id ELSE s.viewer_user_id END
             LEFT JOIN devices d ON d.id = s.host_device_id
             WHERE s.viewer_user_id = $1 OR s.host_user_id = $1
             ORDER BY s.started_at DESC LIMIT 100",
        )
        .bind(user.user_id)
        .fetch_all(&state.db)
        .await?,
    ))
}
