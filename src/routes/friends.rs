//! Friends (Discord-style requests by username), blocks, and what each friend may do
//! on your devices.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::me::PublicUser;
use crate::AppState;
use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult, bad};
use crate::hub::Event;

#[derive(Serialize, Deserialize, sqlx::FromRow, Clone, Copy, Debug)]
pub struct Permissions {
    pub connect_without_approval: bool,
    pub control_input: bool,
    pub hear_audio: bool,
    pub use_clipboard: bool,
    pub transfer_files: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            connect_without_approval: false,
            control_input: true,
            hear_audio: true,
            use_clipboard: false,
            transfer_files: false,
        }
    }
}

/// What `owner` lets `friend` do (defaults when never set).
pub async fn permissions_for(db: &sqlx::PgPool, owner: Uuid, friend: Uuid) -> ApiResult<Permissions> {
    let p: Option<Permissions> = sqlx::query_as(
        "SELECT connect_without_approval, control_input, hear_audio, use_clipboard, transfer_files
         FROM friend_permissions WHERE owner_id = $1 AND friend_id = $2",
    )
    .bind(owner)
    .bind(friend)
    .fetch_optional(db)
    .await?;
    Ok(p.unwrap_or_default())
}

pub async fn are_friends(db: &sqlx::PgPool, a: Uuid, b: Uuid) -> ApiResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM friendships WHERE status = 'accepted'
           AND LEAST(requester_id, addressee_id) = LEAST($1::uuid, $2::uuid)
           AND GREATEST(requester_id, addressee_id) = GREATEST($1::uuid, $2::uuid))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(db)
    .await?)
}

#[derive(Serialize)]
pub struct FriendDevice {
    pub id: Uuid,
    pub name: String,
    pub platform: String,
    pub online: bool,
}

#[derive(Serialize)]
pub struct Friend {
    pub user: PublicUser,
    /// "friend", "incoming" (they asked you), "outgoing" (you asked them).
    pub state: String,
    pub since: DateTime<Utc>,
    pub devices: Vec<FriendDevice>,
    /// Connected, or gone less than a minute ago.
    pub online: bool,
    /// Seconds since they were last connected (when offline; None = never).
    pub last_seen_ago_secs: Option<i64>,
    /// What you allow them to do on your devices.
    pub you_allow: Permissions,
    /// What they allow you to do on theirs.
    pub they_allow: Permissions,
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<Friend>>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        username: String,
        display_name: String,
        avatar_url: Option<String>,
        status: String,
        requester_id: Uuid,
        since: DateTime<Utc>,
        last_seen_ago: Option<i64>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT u.id, u.username::text AS username, u.display_name, u.avatar_url, f.status::text AS status, f.requester_id,
                COALESCE(f.responded_at, f.created_at) AS since,
                EXTRACT(EPOCH FROM (now() - u.last_seen_at))::bigint AS last_seen_ago
         FROM friendships f
         JOIN users u ON u.id = CASE WHEN f.requester_id = $1 THEN f.addressee_id ELSE f.requester_id END
         WHERE (f.requester_id = $1 OR f.addressee_id = $1) AND u.status = 'active'
         ORDER BY u.display_name",
    )
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let friend_state = match (r.status.as_str(), r.requester_id == user.user_id) {
            ("accepted", _) => "friend",
            (_, true) => "outgoing",
            (_, false) => "incoming",
        };
        let mut device_ids: Vec<Uuid> = Vec::new();
        let devices = if friend_state == "friend" {
            #[derive(sqlx::FromRow)]
            struct D {
                id: Uuid,
                name: String,
                platform: String,
            }
            let ds: Vec<D> = sqlx::query_as(
                "SELECT id, name, platform::text AS platform FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY last_seen_at DESC NULLS LAST",
            )
            .bind(r.id)
            .fetch_all(&state.db)
            .await?;
            device_ids = ds.iter().map(|d| d.id).collect();
            ds.into_iter()
                .map(|d| FriendDevice { online: state.hub.is_online(d.id), id: d.id, name: d.name, platform: d.platform })
                .collect()
        } else {
            Vec::new()
        };
        let online = friend_state == "friend" && device_ids.iter().any(|d| state.hub.is_present(*d));
        out.push(Friend {
            you_allow: permissions_for(&state.db, user.user_id, r.id).await?,
            they_allow: permissions_for(&state.db, r.id, user.user_id).await?,
            user: PublicUser { id: r.id, username: r.username, display_name: r.display_name, avatar_url: r.avatar_url },
            state: friend_state.into(),
            since: r.since,
            devices,
            online,
            last_seen_ago_secs: if online || friend_state != "friend" { None } else { r.last_seen_ago.map(|s| s.max(0)) },
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct AddFriend {
    pub username: String,
}

/// Sends a request by exact username. If they already asked you, you become friends.
pub async fn request(State(state): State<AppState>, user: AuthUser, Json(req): Json<AddFriend>) -> ApiResult<Json<serde_json::Value>> {
    let name = req.username.trim().trim_start_matches('@').to_lowercase();
    let target: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND status = 'active'")
        .bind(&name)
        .fetch_optional(&state.db)
        .await?;
    // Same answer for "doesn't exist" and "blocked you": don't leak blocks.
    let not_found = || bad("user_not_found", "Hm, didn't work. Double-check the username.");
    let target = target.ok_or_else(not_found)?;
    if target == user.user_id {
        return Err(bad("self", "That's you!"));
    }
    let blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1))",
    )
    .bind(user.user_id)
    .bind(target)
    .fetch_one(&state.db)
    .await?;
    if blocked {
        return Err(not_found());
    }
    #[derive(sqlx::FromRow)]
    struct Existing {
        id: Uuid,
        status: String,
        requester_id: Uuid,
    }
    let existing: Option<Existing> = sqlx::query_as(
        "SELECT id, status::text AS status, requester_id FROM friendships
         WHERE LEAST(requester_id, addressee_id) = LEAST($1::uuid, $2::uuid) AND GREATEST(requester_id, addressee_id) = GREATEST($1::uuid, $2::uuid)",
    )
    .bind(user.user_id)
    .bind(target)
    .fetch_optional(&state.db)
    .await?;
    let result = match existing {
        Some(e) if e.status == "accepted" => "already_friends",
        Some(e) if e.requester_id == user.user_id => "already_requested",
        Some(e) => {
            sqlx::query("UPDATE friendships SET status = 'accepted', responded_at = now() WHERE id = $1").bind(e.id).execute(&state.db).await?;
            state.hub.notify_user(target, Event::FriendsChanged);
            "accepted"
        }
        None => {
            sqlx::query("INSERT INTO friendships (requester_id, addressee_id) VALUES ($1, $2)")
                .bind(user.user_id)
                .bind(target)
                .execute(&state.db)
                .await?;
            state.hub.notify_user(target, Event::FriendsChanged);
            "requested"
        }
    };
    Ok(Json(json!({ "result": result, "user_id": target })))
}

pub async fn accept(State(state): State<AppState>, user: AuthUser, Path(other): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let n = sqlx::query(
        "UPDATE friendships SET status = 'accepted', responded_at = now()
         WHERE requester_id = $1 AND addressee_id = $2 AND status = 'pending'",
    )
    .bind(other)
    .bind(user.user_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    state.hub.notify_user(other, Event::FriendsChanged);
    Ok(Json(json!({ "ok": true })))
}

/// Removes a friend, cancels your request, or declines theirs.
pub async fn remove(State(state): State<AppState>, user: AuthUser, Path(other): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "DELETE FROM friendships WHERE LEAST(requester_id, addressee_id) = LEAST($1::uuid, $2::uuid)
           AND GREATEST(requester_id, addressee_id) = GREATEST($1::uuid, $2::uuid)",
    )
    .bind(user.user_id)
    .bind(other)
    .execute(&mut *tx)
    .await?;
    // Permissions only make sense between friends.
    sqlx::query("DELETE FROM friend_permissions WHERE (owner_id = $1 AND friend_id = $2) OR (owner_id = $2 AND friend_id = $1)")
        .bind(user.user_id)
        .bind(other)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.hub.notify_user(other, Event::FriendsChanged);
    Ok(Json(json!({ "ok": true })))
}

pub async fn block(State(state): State<AppState>, user: AuthUser, Path(other): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    if other == user.user_id {
        return Err(bad("self", "You can't block yourself"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(user.user_id)
        .bind(other)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM friendships WHERE LEAST(requester_id, addressee_id) = LEAST($1::uuid, $2::uuid)
           AND GREATEST(requester_id, addressee_id) = GREATEST($1::uuid, $2::uuid)",
    )
    .bind(user.user_id)
    .bind(other)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM friend_permissions WHERE (owner_id = $1 AND friend_id = $2) OR (owner_id = $2 AND friend_id = $1)")
        .bind(user.user_id)
        .bind(other)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.hub.notify_user(other, Event::FriendsChanged);
    Ok(Json(json!({ "ok": true })))
}

pub async fn unblock(State(state): State<AppState>, user: AuthUser, Path(other): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(user.user_id)
        .bind(other)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn blocked(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<PublicUser>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT u.id, u.username::text AS username, u.display_name, u.avatar_url
             FROM user_blocks b JOIN users u ON u.id = b.blocked_id WHERE b.blocker_id = $1 ORDER BY b.created_at DESC",
        )
        .bind(user.user_id)
        .fetch_all(&state.db)
        .await?,
    ))
}

/// Sets what a friend may do on your devices (e.g. connect without asking).
pub async fn set_permissions(
    State(state): State<AppState>,
    user: AuthUser,
    Path(friend): Path<Uuid>,
    Json(p): Json<Permissions>,
) -> ApiResult<Json<Permissions>> {
    if !are_friends(&state.db, user.user_id, friend).await? {
        return Err(ApiError::NotFound);
    }
    sqlx::query(
        "INSERT INTO friend_permissions (owner_id, friend_id, connect_without_approval, control_input, hear_audio, use_clipboard, transfer_files)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (owner_id, friend_id) DO UPDATE SET
           connect_without_approval = EXCLUDED.connect_without_approval, control_input = EXCLUDED.control_input,
           hear_audio = EXCLUDED.hear_audio, use_clipboard = EXCLUDED.use_clipboard, transfer_files = EXCLUDED.transfer_files",
    )
    .bind(user.user_id)
    .bind(friend)
    .bind(p.connect_without_approval)
    .bind(p.control_input)
    .bind(p.hear_audio)
    .bind(p.use_clipboard)
    .bind(p.transfer_files)
    .execute(&state.db)
    .await?;
    state.hub.notify_user(friend, Event::FriendsChanged);
    Ok(Json(p))
}
