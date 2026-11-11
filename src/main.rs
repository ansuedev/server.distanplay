//! Distanplay server: accounts (Discord sign-in), friends, synced recents/favorites,
//! and the handshake + relay that lets friends connect when they aren't on the same
//! network. Built for Railway: one binary, Postgres, config from env.

mod auth;
mod config;
mod limit;
mod error;
mod hub;
mod routes;
mod username;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::routing::{delete, get, patch, post, put};
use axum::{Router, extract::DefaultBodyLimit};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::error::{ApiError, ApiResult};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub cfg: Arc<config::Config>,
    pub http: reqwest::Client,
    pub hub: Arc<hub::Hub>,
    pub ticket_key: Arc<ed25519_dalek::SigningKey>,
    pub limits: Arc<limit::Limiter>,
}

/// The caller's IP: Railway (and most proxies) put it first in `X-Forwarded-For`.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(peer.ip())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,distanplay_server=debug,tower_http=info,sqlx=warn".into()),
        )
        .init();

    let cfg = config::Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&cfg.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("database ready");

    let state = AppState {
        ticket_key: Arc::new(ed25519_dalek::SigningKey::from_bytes(&cfg.ticket_seed)),
        http: reqwest::Client::builder().timeout(Duration::from_secs(15)).user_agent("distanplay-server").build()?,
        hub: Arc::new(hub::Hub::default()),
        limits: Arc::new(limit::Limiter::default()),
        cfg: Arc::new(cfg),
        db,
    };
    tokio::spawn(housekeeping(state.clone()));

    let api = Router::new()
        // auth
        .route("/auth/discord/start", post(auth::discord::start))
        .route("/auth/discord/callback", get(auth::discord::callback))
        .route("/auth/poll", post(auth::discord::poll))
        .route("/auth/refresh", post(refresh))
        .merge(dev_routes())
        .route("/auth/logout", post(logout))
        .route("/auth/sessions", get(routes::me::sessions))
        .route("/auth/sessions/{family_id}", delete(routes::me::revoke_session))
        // me
        .route("/me", get(routes::me::me).patch(routes::me::update_me))
        .route("/me/devices", get(routes::me::devices))
        .route("/me/devices/{id}", patch(routes::me::rename_device).delete(routes::me::remove_device))
        .route("/users/by-username/{username}", get(routes::me::find_user))
        // friends
        .route("/friends", get(routes::friends::list))
        .route("/friends/requests", post(routes::friends::request))
        .route("/friends/{user_id}/accept", post(routes::friends::accept))
        .route("/friends/{user_id}", delete(routes::friends::remove))
        .route("/friends/{user_id}/permissions", put(routes::friends::set_permissions))
        .route("/blocks", get(routes::friends::blocked))
        .route("/blocks/{user_id}", put(routes::friends::block).delete(routes::friends::unblock))
        // library
        .route("/recents", get(routes::library::recents).post(routes::library::touch_recent))
        .route("/recents/{id}", delete(routes::library::remove_recent))
        .route("/favorites", get(routes::library::favorites).post(routes::library::add_favorite))
        .route("/favorites/order", put(routes::library::reorder_favorites))
        .route("/favorites/{id}", delete(routes::library::remove_favorite))
        .route("/history", get(routes::library::history))
        // live
        .route("/ws", get(hub::ws))
        .route("/config", get(public_config))
        // admin
        .route("/admin/users", get(routes::admin::users))
        .route("/admin/users/{id}/status", put(routes::admin::set_status))
        .route("/admin/users/{id}/roles", post(routes::admin::grant_role))
        .route("/admin/users/{id}/roles/{role}", delete(routes::admin::revoke_role))
        .route("/admin/live", get(routes::admin::live));

    let app = Router::new()
        .nest("/v1", api)
        .route("/", get(|| async { "Distanplay server" }))
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(
            // The desktop app doesn't need CORS; this is for the future web admin.
            CorsLayer::new()
                .allow_origin(
                    std::env::var("ADMIN_ORIGIN")
                        .ok()
                        .and_then(|o| o.parse::<HeaderValue>().ok())
                        .map(tower_http::cors::AllowOrigin::exact)
                        .unwrap_or_else(|| tower_http::cors::AllowOrigin::list(Vec::<HeaderValue>::new())),
                )
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], state.cfg.port));
    tracing::info!("listening on {addr} (public URL {})", state.cfg.public_url);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Debug builds only, and only with DEV_LOGIN=1: sign in as any username without
/// Discord (for local testing). Never compiled into release builds.
#[cfg(debug_assertions)]
fn dev_routes() -> Router<AppState> {
    if std::env::var("DEV_LOGIN").as_deref() == Ok("1") {
        tracing::warn!("DEV_LOGIN is on: /v1/auth/dev signs anyone in (debug build only)");
        Router::new().route("/auth/dev", post(dev_login))
    } else {
        Router::new()
    }
}

#[cfg(not(debug_assertions))]
fn dev_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(debug_assertions)]
#[derive(Deserialize)]
struct DevLogin {
    username: String,
    install_id: uuid::Uuid,
    device_name: String,
}

#[cfg(debug_assertions)]
async fn dev_login(State(state): State<AppState>, Json(b): Json<DevLogin>) -> ApiResult<Json<serde_json::Value>> {
    let uname = username::normalize(&b.username);
    let uid: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, display_name) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET last_login_at = now() RETURNING id",
    )
    .bind(&uname)
    .bind(&b.username)
    .fetch_one(&state.db)
    .await?;
    sqlx::query("INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE is_default ON CONFLICT DO NOTHING")
        .bind(uid)
        .execute(&state.db)
        .await?;
    let device: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO devices (user_id, install_id, name, platform) VALUES ($1, $2, $3, 'other')
         ON CONFLICT (user_id, install_id) DO UPDATE SET name = EXCLUDED.name, revoked_at = NULL RETURNING id",
    )
    .bind(uid)
    .bind(b.install_id)
    .bind(&b.device_name)
    .fetch_one(&state.db)
    .await?;
    let t = auth::issue(&state, uid, Some(device), "password", None, None).await?;
    Ok(Json(json!({
        "access_token": t.access_token, "refresh_token": t.refresh_token, "device_id": device,
        "me": routes::me::load_me(&state.db, uid).await?,
    })))
}

async fn health(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("SELECT 1").execute(&state.db).await?;
    Ok(Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") })))
}

/// What apps need before signing in: STUN servers, relay options and the public key
/// that verifies connection tickets.
async fn public_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "stun": state.cfg.stun_servers,
        "relay": { "ws": state.cfg.ws_relay, "udp": state.cfg.udp_relay },
        "ticket_public_key": base64::engine::general_purpose::STANDARD.encode(state.ticket_key.verifying_key().to_bytes()),
        "providers": ["discord"],
    }))
}

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<RefreshBody>,
) -> ApiResult<Json<serde_json::Value>> {
    state.limits.check("refresh", client_ip(&headers, addr), 30)?;
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let t = auth::refresh(&state, b.refresh_token.trim(), Some(client_ip(&headers, addr)), ua).await?;
    Ok(Json(json!({
        "access_token": t.access_token,
        "access_expires_at": t.access_expires_at,
        "refresh_token": t.refresh_token,
    })))
}

/// Signs this app out (revokes its refresh token family).
async fn logout(State(state): State<AppState>, user: auth::AuthUser) -> ApiResult<Json<serde_json::Value>> {
    auth::revoke_family(&state.db, user.family_id, "logout").await?;
    if let Some(d) = user.device_id {
        state.hub.kick_device(d);
    }
    Ok(Json(json!({ "ok": true })))
}

/// Periodic cleanup: expired sign-in attempts and long-dead refresh tokens.
async fn housekeeping(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(600));
    loop {
        tick.tick().await;
        let r: Result<(), ApiError> = async {
            sqlx::query("UPDATE login_requests SET status = 'expired' WHERE status IN ('pending', 'completed') AND expires_at < now()")
                .execute(&state.db)
                .await?;
            sqlx::query("DELETE FROM login_requests WHERE created_at < now() - interval '7 days'").execute(&state.db).await?;
            // Rotated/revoked/expired refresh rows are only needed briefly for reuse detection.
            sqlx::query(
                "DELETE FROM auth_sessions WHERE (rotated_at < now() - interval '30 days')
                    OR (revoked_at < now() - interval '30 days') OR (expires_at < now() - interval '30 days')",
            )
            .execute(&state.db)
            .await?;
            sqlx::query("UPDATE connection_requests SET status = 'expired' WHERE status = 'pending' AND expires_at < now()")
                .execute(&state.db)
                .await?;
            state.limits.prune();
            Ok(())
        }
        .await;
        if let Err(e) = r {
            tracing::warn!("housekeeping: {e}");
        }
    }
}
