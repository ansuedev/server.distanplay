//! Live connections from signed-in apps (one WebSocket per device).
//!
//! The hub does four jobs:
//! 1. **Presence**: friends see which of your devices are online.
//! 2. **Connection requests**: a friend asks to connect to one of your devices; it's
//!    approved automatically if you allow that friend to connect without asking,
//!    otherwise your app shows a prompt.
//! 3. **Handshake**: once approved, both apps get a session id, a fresh 32-byte session
//!    key (so no password is needed between friends) and a ticket signed by the server.
//!    They then swap their candidate addresses (LAN + public address from STUN)
//!    through the hub and punch through their routers to talk directly (UDP).
//! 4. **Relay**: if punching fails (strict NAT / CGNAT), media flows through the hub
//!    over the WebSocket. Railway has no public UDP, so this TCP relay is the fallback;
//!    a UDP relay elsewhere can be configured with `UDP_RELAY`.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::Response;
use base64::Engine;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::AppState;
use crate::auth::{AuthUser, TicketClaims, sign_ticket};
use crate::error::{ApiError, ApiResult};
use crate::routes::friends::{are_friends, permissions_for};

const REQUEST_TTL: Duration = Duration::from_secs(60);
/// A device that disconnects still shows as online this long (absorbs Wi-Fi blips
/// and app restarts); after that friends see "last seen".
pub const PRESENCE_GRACE: Duration = Duration::from_secs(60);
/// How often a connected device refreshes its last-seen time in the database.
const SEEN_EVERY: Duration = Duration::from_secs(60);
const TICKET_TTL_SECS: i64 = 120;
/// Relay frames start with the 16-byte session id.
const RELAY_HEADER: usize = 16;
/// Max relayed bytes per second per session (keeps one stream from starving the box).
const RELAY_MAX_BPS: u64 = 50_000_000 / 8;

/// Events other parts of the server push to apps.
pub enum Event {
    FriendsChanged,
}

struct DeviceConn {
    user_id: Uuid,
    conn_id: Uuid,
    tx: mpsc::UnboundedSender<Message>,
}

struct Pending {
    viewer_user: Uuid,
    viewer_device: Uuid,
    host_user: Uuid,
    host_device: Uuid,
    created: Instant,
}

struct Session {
    db_id: Uuid,
    host_device: Uuid,
    viewer_device: Uuid,
    relay_host: AtomicBool,
    relay_viewer: AtomicBool,
    relayed: AtomicU64,
    window: parking_window::Window,
}

mod parking_window {
    use std::sync::Mutex;
    use std::time::Instant;

    /// Bytes relayed in the current one-second window (simple rate limit).
    pub struct Window(Mutex<(Instant, u64)>);

    impl Window {
        pub fn new() -> Self {
            Self(Mutex::new((Instant::now(), 0)))
        }

        /// Adds `n` bytes; false if this second's budget is used up.
        pub fn take(&self, n: u64, max: u64) -> bool {
            let mut w = self.0.lock().expect("not poisoned");
            if w.0.elapsed().as_secs_f32() >= 1.0 {
                *w = (Instant::now(), 0);
            }
            if w.1 + n > max {
                return false;
            }
            w.1 += n;
            true
        }
    }
}

#[derive(Default)]
pub struct Hub {
    devices: DashMap<Uuid, DeviceConn>,
    /// Devices that disconnected recently (still shown online during the grace period).
    left: DashMap<Uuid, Instant>,
    pending: DashMap<Uuid, Pending>,
    sessions: DashMap<Uuid, Arc<Session>>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Connect { device_id: Uuid },
    /// Connect with a device's code + password (anyone signed in, no friendship needed).
    ConnectCode { code: String, password: String },
    /// Connect with an invite link's token (`/j/<token>`, from Discord or a profile).
    ConnectInvite { token: String },
    Cancel { request_id: Uuid },
    Respond { request_id: Uuid, accept: bool },
    Candidates { session_id: Uuid, candidates: Vec<Candidate> },
    Relay { session_id: Uuid },
    Route { session_id: Uuid, route: String },
    End { session_id: Uuid, reason: Option<String> },
    Ping,
}

#[derive(Serialize, Deserialize, Clone)]
struct Candidate {
    /// "ip:port"
    addr: String,
    /// "host" (LAN), "srflx" (public, from STUN), "relay".
    kind: String,
}

impl Hub {
    /// Connected right now (can be connected to).
    pub fn is_online(&self, device: Uuid) -> bool {
        self.devices.contains_key(&device)
    }

    /// Shown as online: connected, or disconnected less than a minute ago.
    pub fn is_present(&self, device: Uuid) -> bool {
        self.is_online(device) || self.left.get(&device).is_some_and(|t| t.elapsed() < PRESENCE_GRACE)
    }

    fn send(&self, device: Uuid, v: serde_json::Value) {
        if let Some(c) = self.devices.get(&device) {
            let _ = c.tx.send(Message::Text(Utf8Bytes::from(v.to_string())));
        }
    }

    /// A user's devices connected right now.
    pub fn online_devices(&self, user: Uuid) -> Vec<Uuid> {
        self.user_devices(user)
    }

    fn user_devices(&self, user: Uuid) -> Vec<Uuid> {
        self.devices.iter().filter(|e| e.value().user_id == user).map(|e| *e.key()).collect()
    }

    pub fn notify_user(&self, user: Uuid, ev: Event) {
        let msg = match ev {
            Event::FriendsChanged => json!({ "type": "friends_changed" }),
        };
        for d in self.user_devices(user) {
            self.send(d, msg.clone());
        }
    }

    pub fn kick_device(&self, device: Uuid) {
        if let Some((_, c)) = self.devices.remove(&device) {
            let _ = c.tx.send(Message::Close(Some(CloseFrame { code: 4001, reason: "device removed".into() })));
        }
    }

    pub fn stats(&self) -> serde_json::Value {
        json!({
            "devices_online": self.devices.len(),
            "pending_requests": self.pending.len(),
            "sessions": self.sessions.len(),
            "relaying": self.sessions.iter().filter(|s| s.relay_host.load(Ordering::Relaxed) && s.relay_viewer.load(Ordering::Relaxed)).count(),
        })
    }
}

#[derive(Deserialize)]
pub struct WsQuery {
    access_token: Option<String>,
}

/// `GET /v1/ws` — upgrade with `Authorization: Bearer …` (or `?access_token=`).
pub async fn ws(
    State(state): State<AppState>,
    Query(q): Query<WsQuery>,
    headers: axum::http::HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let header_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string);
    let token = header_token.or(q.access_token).ok_or(ApiError::Unauthorized)?;
    let user = AuthUser::from_token(&state, token.trim()).await?;
    let device = user.device_id.ok_or(ApiError::Forbidden("this sign-in has no device".into()))?;
    Ok(upgrade.max_message_size(2 * 1024 * 1024).on_upgrade(move |socket| run(state, user, device, socket)))
}

async fn run(state: AppState, user: AuthUser, device: Uuid, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let conn_id = Uuid::new_v4();
    // One live connection per device: a reconnect replaces the old one.
    if let Some(old) = state.hub.devices.insert(device, DeviceConn { user_id: user.user_id, conn_id, tx: tx.clone() }) {
        let _ = old.tx.send(Message::Close(Some(CloseFrame { code: 4000, reason: "replaced".into() })));
    }
    touch_seen(&state, user.user_id, device).await;
    // Back within the grace period: friends never saw us go, so no announcement.
    let returning = state.hub.left.remove(&device).is_some_and(|(_, t)| t.elapsed() < PRESENCE_GRACE);
    if !returning {
        broadcast_presence(&state, user.user_id, device, true).await;
    }
    let mut last_touch = Instant::now();
    let _ = tx.send(Message::Text(Utf8Bytes::from(
        json!({
            "type": "hello",
            "device_id": device,
            "stun": state.cfg.stun_servers,
            "relay": { "ws": state.cfg.ws_relay, "udp": state.cfg.udp_relay },
        })
        .to_string(),
    )));

    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let close = matches!(m, Message::Close(_));
            if sink.send(m).await.is_err() || close {
                break;
            }
        }
    });

    // Keep the connection honest: drop it if nothing arrives for 75 s (apps ping every 25 s).
    loop {
        let next = tokio::time::timeout(Duration::from_secs(75), stream.next()).await;
        let msg = match next {
            Ok(Some(Ok(m))) => m,
            _ => break,
        };
        match msg {
            Message::Text(t) => match serde_json::from_str::<ClientMsg>(&t) {
                Ok(m) => handle(&state, &user, device, &tx, m).await,
                Err(e) => {
                    let _ = tx.send(error_msg("bad_message", &e.to_string()));
                }
            },
            Message::Binary(b) => relay(&state, device, &b),
            Message::Ping(p) => {
                let _ = tx.send(Message::Pong(p));
            }
            Message::Close(_) => break,
            Message::Pong(_) => {}
        }
        // Heartbeat: keep "last seen" fresh while connected.
        if last_touch.elapsed() >= SEEN_EVERY {
            last_touch = Instant::now();
            touch_seen(&state, user.user_id, device).await;
        }
        // Another connection for this device took over.
        if state.hub.devices.get(&device).is_none_or(|c| c.conn_id != conn_id) {
            break;
        }
    }

    writer.abort();
    let still_ours = state.hub.devices.get(&device).is_some_and(|c| c.conn_id == conn_id);
    if still_ours {
        state.hub.devices.remove(&device);
        touch_seen(&state, user.user_id, device).await;
        end_sessions_of(&state, device, "disconnected").await;
        // Announce "offline" only if it doesn't come back within the grace period.
        let left_at = Instant::now();
        state.hub.left.insert(device, left_at);
        let st = state.clone();
        let user_id = user.user_id;
        tokio::spawn(async move {
            tokio::time::sleep(PRESENCE_GRACE).await;
            let gone = st.hub.left.remove_if(&device, |_, t| *t == left_at).is_some();
            if gone && !st.hub.is_online(device) {
                broadcast_presence(&st, user_id, device, false).await;
            }
        });
    }
}

/// Updates the device's and the user's last-seen time.
async fn touch_seen(state: &AppState, user: Uuid, device: Uuid) {
    let _ = sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1").bind(device).execute(&state.db).await;
    let _ = sqlx::query("UPDATE users SET last_seen_at = now() WHERE id = $1").bind(user).execute(&state.db).await;
}

fn error_msg(code: &str, message: &str) -> Message {
    Message::Text(Utf8Bytes::from(json!({ "type": "error", "code": code, "message": message }).to_string()))
}

async fn broadcast_presence(state: &AppState, user: Uuid, device: Uuid, online: bool) {
    let friends: Vec<Uuid> = sqlx::query_scalar(
        "SELECT CASE WHEN requester_id = $1 THEN addressee_id ELSE requester_id END
         FROM friendships WHERE status = 'accepted' AND (requester_id = $1 OR addressee_id = $1)",
    )
    .bind(user)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let msg = json!({ "type": "presence", "user_id": user, "device_id": device, "online": online });
    for f in friends.into_iter().chain(std::iter::once(user)) {
        for d in state.hub.user_devices(f) {
            if d != device {
                state.hub.send(d, msg.clone());
            }
        }
    }
}

async fn handle(state: &AppState, user: &AuthUser, device: Uuid, tx: &mpsc::UnboundedSender<Message>, m: ClientMsg) {
    let reply = |v: serde_json::Value| {
        let _ = tx.send(Message::Text(Utf8Bytes::from(v.to_string())));
    };
    match m {
        ClientMsg::Ping => reply(json!({ "type": "pong" })),

        ClientMsg::Connect { device_id } => {
            if let Err(e) = connect(state, user, device, device_id, &reply).await {
                tracing::warn!("connect: {e}");
                reply(json!({ "type": "connect_failed", "device_id": device_id, "reason": "error" }));
            }
        }

        ClientMsg::ConnectCode { code, password } => {
            if let Err(e) = connect_code(state, user, device, &code, &password, &reply).await {
                tracing::warn!("connect_code: {e}");
                reply(json!({ "type": "connect_failed", "reason": "error" }));
            }
        }

        ClientMsg::ConnectInvite { token } => {
            if let Err(e) = connect_invite(state, user, device, &token, &reply).await {
                tracing::warn!("connect_invite: {e}");
                reply(json!({ "type": "connect_failed", "reason": "error" }));
            }
        }

        ClientMsg::Cancel { request_id } => {
            if let Some((_, p)) = state.hub.pending.remove_if(&request_id, |_, p| p.viewer_device == device) {
                let _ = sqlx::query("UPDATE connection_requests SET status = 'canceled', responded_at = now() WHERE id = $1")
                    .bind(request_id)
                    .execute(&state.db)
                    .await;
                state.hub.send(p.host_device, json!({ "type": "request_canceled", "request_id": request_id }));
            }
        }

        ClientMsg::Respond { request_id, accept } => {
            let Some((_, p)) = state.hub.pending.remove_if(&request_id, |_, p| p.host_device == device) else {
                return;
            };
            let status = if accept { "approved" } else { "denied" };
            let _ = sqlx::query("UPDATE connection_requests SET status = $2::connection_request_status, responded_at = now() WHERE id = $1")
                .bind(request_id)
                .bind(status)
                .execute(&state.db)
                .await;
            if accept {
                if let Err(e) = start_session(state, Some(request_id), p.viewer_user, p.viewer_device, p.host_user, p.host_device).await {
                    tracing::error!("start session: {e}");
                }
            } else {
                state.hub.send(p.viewer_device, json!({ "type": "connect_failed", "request_id": request_id, "device_id": p.host_device, "reason": "denied" }));
            }
        }

        ClientMsg::Candidates { session_id, candidates } => {
            let Some(s) = state.hub.sessions.get(&session_id).map(|s| s.clone()) else { return };
            let Some(peer) = other_side(&s, device) else { return };
            let candidates: Vec<Candidate> = candidates.into_iter().take(16).filter(|c| c.addr.parse::<std::net::SocketAddr>().is_ok()).collect();
            state.hub.send(peer, json!({ "type": "candidates", "session_id": session_id, "candidates": candidates }));
        }

        ClientMsg::Relay { session_id } => {
            if !state.cfg.ws_relay {
                reply(json!({ "type": "relay_unavailable", "session_id": session_id }));
                return;
            }
            let Some(s) = state.hub.sessions.get(&session_id).map(|s| s.clone()) else { return };
            let Some(peer) = other_side(&s, device) else { return };
            if device == s.host_device {
                s.relay_host.store(true, Ordering::SeqCst);
            } else {
                s.relay_viewer.store(true, Ordering::SeqCst);
            }
            if s.relay_host.load(Ordering::SeqCst) && s.relay_viewer.load(Ordering::SeqCst) {
                let m = json!({ "type": "relay_ready", "session_id": session_id });
                state.hub.send(device, m.clone());
                state.hub.send(peer, m);
                let _ = sqlx::query("UPDATE connection_sessions SET route = 'relay_tcp' WHERE id = $1").bind(s.db_id).execute(&state.db).await;
            }
        }

        ClientMsg::Route { session_id, route } => {
            let Some(s) = state.hub.sessions.get(&session_id).map(|s| s.clone()) else { return };
            if other_side(&s, device).is_none() {
                return;
            }
            let route = match route.as_str() {
                "lan" | "direct" | "punched" | "relay_tcp" | "relay_udp" => route,
                _ => "unknown".into(),
            };
            let _ = sqlx::query("UPDATE connection_sessions SET route = $2::connection_route WHERE id = $1")
                .bind(s.db_id)
                .bind(route)
                .execute(&state.db)
                .await;
        }

        ClientMsg::End { session_id, reason } => {
            let ok = state.hub.sessions.get(&session_id).is_some_and(|s| other_side(&s, device).is_some());
            if ok {
                end_session(state, session_id, reason.as_deref().unwrap_or("ended")).await;
            }
        }
    }
    let _ = user;
}

fn other_side(s: &Session, device: Uuid) -> Option<Uuid> {
    if device == s.host_device {
        Some(s.viewer_device)
    } else if device == s.viewer_device {
        Some(s.host_device)
    } else {
        None
    }
}

async fn connect(
    state: &AppState,
    user: &AuthUser,
    my_device: Uuid,
    target: Uuid,
    reply: &impl Fn(serde_json::Value),
) -> ApiResult<()> {
    let fail = |reason: &str| reply(json!({ "type": "connect_failed", "device_id": target, "reason": reason }));
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM devices WHERE id = $1 AND revoked_at IS NULL")
        .bind(target)
        .fetch_optional(&state.db)
        .await?;
    let Some(owner) = owner else {
        fail("not_found");
        return Ok(());
    };
    if target == my_device {
        fail("self");
        return Ok(());
    }
    // Your own devices are always allowed; otherwise you must be friends.
    let own = owner == user.user_id;
    if !own && !are_friends(&state.db, user.user_id, owner).await? {
        fail("forbidden");
        return Ok(());
    }
    if !state.hub.is_online(target) {
        fail("offline");
        return Ok(());
    }
    let auto = own || permissions_for(&state.db, owner, user.user_id).await?.connect_without_approval;
    request_connection(state, user, my_device, owner, target, auto, reply).await
}

/// An invite link: whoever it's for (or anyone, for an open invite) may connect.
async fn connect_invite(
    state: &AppState,
    user: &AuthUser,
    my_device: Uuid,
    token: &str,
    reply: &impl Fn(serde_json::Value),
) -> ApiResult<()> {
    match crate::routes::invites::redeem(state, token, user.user_id, my_device).await? {
        Err(reason) => {
            reply(json!({ "type": "connect_failed", "reason": reason }));
            Ok(())
        }
        Ok(r) => {
            // A friend who may connect without asking doesn't need approval either.
            let auto = r.auto
                || (are_friends(&state.db, user.user_id, r.host_user).await?
                    && permissions_for(&state.db, r.host_user, user.user_id).await?.connect_without_approval);
            request_connection(state, user, my_device, r.host_user, r.host_device, auto, reply).await
        }
    }
}

/// Starts the session right away (`auto`) or asks the host's app, which shows a prompt.
async fn request_connection(
    state: &AppState,
    user: &AuthUser,
    my_device: Uuid,
    owner: Uuid,
    target: Uuid,
    auto: bool,
    reply: &impl Fn(serde_json::Value),
) -> ApiResult<()> {
    let request_id: Uuid = sqlx::query_scalar(
        "INSERT INTO connection_requests (viewer_user_id, viewer_device_id, host_user_id, host_device_id, status, expires_at, responded_at)
         VALUES ($1, $2, $3, $4, $5::connection_request_status, now() + interval '60 seconds', CASE WHEN $5 = 'auto_approved' THEN now() END)
         RETURNING id",
    )
    .bind(user.user_id)
    .bind(my_device)
    .bind(owner)
    .bind(target)
    .bind(if auto { "auto_approved" } else { "pending" })
    .fetch_one(&state.db)
    .await?;

    if auto {
        start_session(state, Some(request_id), user.user_id, my_device, owner, target).await?;
        return Ok(());
    }

    #[derive(sqlx::FromRow)]
    struct Who {
        username: String,
        display_name: String,
        avatar_url: Option<String>,
        device_name: Option<String>,
    }
    let who: Who = sqlx::query_as(
        "SELECT u.username::text AS username, u.display_name, u.avatar_url, d.name AS device_name
         FROM users u LEFT JOIN devices d ON d.id = $2 WHERE u.id = $1",
    )
    .bind(user.user_id)
    .bind(my_device)
    .fetch_one(&state.db)
    .await?;
    state.hub.pending.insert(
        request_id,
        Pending { viewer_user: user.user_id, viewer_device: my_device, host_user: owner, host_device: target, created: Instant::now() },
    );
    state.hub.send(
        target,
        json!({
            "type": "incoming",
            "request_id": request_id,
            "from": { "id": user.user_id, "username": who.username, "display_name": who.display_name, "avatar_url": who.avatar_url },
            "from_device": { "id": my_device, "name": who.device_name },
            "expires_in": REQUEST_TTL.as_secs(),
        }),
    );
    reply(json!({ "type": "request_sent", "request_id": request_id, "device_id": target }));

    // Expire unanswered requests.
    let st = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(REQUEST_TTL).await;
        if let Some((_, p)) = st.hub.pending.remove_if(&request_id, |_, p| p.created.elapsed() >= REQUEST_TTL) {
            let _ = sqlx::query("UPDATE connection_requests SET status = 'expired' WHERE id = $1 AND status = 'pending'")
                .bind(request_id)
                .execute(&st.db)
                .await;
            st.hub.send(p.viewer_device, json!({ "type": "connect_failed", "request_id": request_id, "device_id": p.host_device, "reason": "no_answer" }));
            st.hub.send(p.host_device, json!({ "type": "request_canceled", "request_id": request_id }));
        }
    });
    Ok(())
}

async fn connect_code(
    state: &AppState,
    user: &AuthUser,
    my_device: Uuid,
    code: &str,
    password: &str,
    reply: &impl Fn(serde_json::Value),
) -> ApiResult<()> {
    let fail = |reason: &str, extra: serde_json::Value| {
        let mut m = json!({ "type": "connect_failed", "reason": reason });
        if let (Some(o), Some(e)) = (m.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        reply(m)
    };
    let Some(code) = crate::routes::access::normalize_code(code) else {
        fail("wrong_credentials", json!({}));
        return Ok(());
    };
    #[derive(sqlx::FromRow)]
    struct Row {
        device_id: Uuid,
        user_id: Uuid,
        password_hash: String,
        failed_attempts: i32,
        locked_secs: Option<i64>,
    }
    let row: Option<Row> = sqlx::query_as(
        "SELECT a.device_id, a.user_id, a.password_hash, a.failed_attempts,
                CASE WHEN a.locked_until > now() THEN EXTRACT(EPOCH FROM (a.locked_until - now()))::bigint END AS locked_secs
         FROM device_access a JOIN devices d ON d.id = a.device_id
         WHERE a.code = $1 AND d.revoked_at IS NULL",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await?;
    // Same answer (and timing) for an unknown code and a wrong password.
    let Some(r) = row else {
        tokio::time::sleep(Duration::from_millis(400)).await;
        fail("wrong_credentials", json!({}));
        return Ok(());
    };
    if let Some(secs) = r.locked_secs {
        fail("locked", json!({ "retry_in": secs.max(1) }));
        return Ok(());
    }
    if !crate::routes::access::verify(password.trim().to_string(), r.password_hash).await {
        // 5 wrong tries lock the code: 30 s, then doubling up to 10 minutes.
        let n = r.failed_attempts + 1;
        let lock = if n >= 5 { Some((30i64 << (n - 5).min(5)).min(600)) } else { None };
        sqlx::query(
            "UPDATE device_access SET failed_attempts = $2,
                locked_until = CASE WHEN $3::bigint IS NULL THEN NULL ELSE now() + make_interval(secs => $3::bigint) END
             WHERE device_id = $1",
        )
        .bind(r.device_id)
        .bind(n)
        .bind(lock)
        .execute(&state.db)
        .await?;
        tokio::time::sleep(Duration::from_millis(400)).await;
        fail("wrong_credentials", json!({}));
        return Ok(());
    }
    sqlx::query("UPDATE device_access SET failed_attempts = 0, locked_until = NULL WHERE device_id = $1")
        .bind(r.device_id)
        .execute(&state.db)
        .await?;
    if r.device_id == my_device {
        fail("self", json!({}));
        return Ok(());
    }
    if !state.hub.is_online(r.device_id) {
        fail("offline", json!({}));
        return Ok(());
    }
    let request_id: Uuid = sqlx::query_scalar(
        "INSERT INTO connection_requests (viewer_user_id, viewer_device_id, host_user_id, host_device_id, status, expires_at, responded_at)
         VALUES ($1, $2, $3, $4, 'auto_approved', now(), now()) RETURNING id",
    )
    .bind(user.user_id)
    .bind(my_device)
    .bind(r.user_id)
    .bind(r.device_id)
    .fetch_one(&state.db)
    .await?;
    start_session(state, Some(request_id), user.user_id, my_device, r.user_id, r.device_id).await
}

async fn start_session(
    state: &AppState,
    request_id: Option<Uuid>,
    viewer_user: Uuid,
    viewer_device: Uuid,
    host_user: Uuid,
    host_device: Uuid,
) -> ApiResult<()> {
    let db_id: Uuid = sqlx::query_scalar(
        "INSERT INTO connection_sessions (request_id, viewer_user_id, viewer_device_id, host_user_id, host_device_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(request_id)
    .bind(viewer_user)
    .bind(viewer_device)
    .bind(host_user)
    .bind(host_device)
    .fetch_one(&state.db)
    .await?;
    let perms = if viewer_user == host_user {
        crate::routes::friends::Permissions { control_input: true, hear_audio: true, use_clipboard: true, ..Default::default() }
    } else {
        permissions_for(&state.db, host_user, viewer_user).await?
    };
    #[derive(sqlx::FromRow)]
    struct Party {
        user_id: Uuid,
        username: String,
        display_name: String,
        avatar_url: Option<String>,
        device_id: Uuid,
        device_name: String,
    }
    let parties: Vec<Party> = sqlx::query_as(
        "SELECT u.id AS user_id, u.username::text AS username, u.display_name, u.avatar_url, d.id AS device_id, d.name AS device_name
         FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = ANY($1)",
    )
    .bind(vec![viewer_device, host_device])
    .fetch_all(&state.db)
    .await?;
    let find = |d: Uuid| parties.iter().find(|p| p.device_id == d);
    let (Some(v), Some(h)) = (find(viewer_device), find(host_device)) else {
        return Err(ApiError::NotFound);
    };
    let party = |p: &Party| {
        json!({
            "user": { "id": p.user_id, "username": p.username, "display_name": p.display_name, "avatar_url": p.avatar_url },
            "device": { "id": p.device_id, "name": p.device_name },
        })
    };

    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let session_key = base64::engine::general_purpose::STANDARD.encode(key);
    let ticket = sign_ticket(
        &state.ticket_key,
        &TicketClaims {
            session_id: db_id,
            host_device_id: host_device,
            viewer_user_id: viewer_user,
            viewer_device_id: Some(viewer_device),
            viewer_name: v.display_name.clone(),
            control_input: perms.control_input,
            hear_audio: perms.hear_audio,
            use_clipboard: perms.use_clipboard,
            exp: chrono::Utc::now().timestamp() + TICKET_TTL_SECS,
        },
    );
    state.hub.sessions.insert(
        db_id,
        Arc::new(Session {
            db_id,
            host_device,
            viewer_device,
            relay_host: AtomicBool::new(false),
            relay_viewer: AtomicBool::new(false),
            relayed: AtomicU64::new(0),
            window: parking_window::Window::new(),
        }),
    );
    let common = |role: &str, peer: &Party| {
        json!({
            "type": "session",
            "session_id": db_id,
            "request_id": request_id,
            "role": role,
            "peer": party(peer),
            "session_key": session_key,
            "ticket": ticket,
            "permissions": perms,
            "stun": state.cfg.stun_servers,
            "relay": { "ws": state.cfg.ws_relay, "udp": state.cfg.udp_relay },
        })
    };
    state.hub.send(host_device, common("host", v));
    state.hub.send(viewer_device, common("viewer", h));
    Ok(())
}

async fn end_session(state: &AppState, id: Uuid, reason: &str) {
    if let Some((_, s)) = state.hub.sessions.remove(&id) {
        let _ = sqlx::query("UPDATE connection_sessions SET ended_at = now(), end_reason = $2, bytes_relayed = $3 WHERE id = $1")
            .bind(s.db_id)
            .bind(reason)
            .bind(s.relayed.load(Ordering::Relaxed) as i64)
            .execute(&state.db)
            .await;
        let m = json!({ "type": "session_end", "session_id": id, "reason": reason });
        state.hub.send(s.host_device, m.clone());
        state.hub.send(s.viewer_device, m);
    }
}

async fn end_sessions_of(state: &AppState, device: Uuid, reason: &str) {
    let ids: Vec<Uuid> = state
        .hub
        .sessions
        .iter()
        .filter(|s| s.host_device == device || s.viewer_device == device)
        .map(|s| *s.key())
        .collect();
    for id in ids {
        end_session(state, id, reason).await;
    }
    let pending: HashSet<Uuid> = state
        .hub
        .pending
        .iter()
        .filter(|p| p.host_device == device || p.viewer_device == device)
        .map(|p| *p.key())
        .collect();
    for id in pending {
        if let Some((_, p)) = state.hub.pending.remove(&id) {
            let other = if p.host_device == device { p.viewer_device } else { p.host_device };
            state.hub.send(other, json!({ "type": "connect_failed", "request_id": id, "device_id": p.host_device, "reason": "offline" }));
        }
    }
}

/// Forwards a relay frame `[session id (16)][payload]` to the other side.
fn relay(state: &AppState, from: Uuid, frame: &[u8]) {
    if frame.len() <= RELAY_HEADER {
        return;
    }
    let Ok(id) = Uuid::from_slice(&frame[..RELAY_HEADER]) else { return };
    let Some(s) = state.hub.sessions.get(&id).map(|s| s.clone()) else { return };
    if !(s.relay_host.load(Ordering::Relaxed) && s.relay_viewer.load(Ordering::Relaxed)) {
        return;
    }
    let Some(to) = other_side(&s, from) else { return };
    if !s.window.take(frame.len() as u64, RELAY_MAX_BPS) {
        return; // over budget: drop (media is loss-tolerant; FEC/ABR adapt)
    }
    s.relayed.fetch_add(frame.len() as u64, Ordering::Relaxed);
    if let Some(c) = state.hub.devices.get(&to) {
        let _ = c.tx.send(Message::Binary(frame.to_vec().into()));
    }
}
