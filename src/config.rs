//! Configuration from environment variables (Railway sets them in the dashboard).

use anyhow::{Context, Result, bail};
use base64::Engine;

#[derive(Clone)]
pub struct Config {
    /// `postgres://…` (Railway: reference the Postgres service's `DATABASE_URL`).
    pub database_url: String,
    /// Port to listen on (Railway sets `PORT`).
    pub port: u16,
    /// Public base URL of this server, e.g. `https://api.distanplay.com` (no trailing
    /// slash). Used for the OAuth redirect URI.
    pub public_url: String,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    /// Secret for signing access tokens (HS256), ≥ 32 bytes, base64.
    pub jwt_secret: Vec<u8>,
    /// Ed25519 seed (32 bytes, base64) for connection tickets hosts can verify offline.
    pub ticket_seed: [u8; 32],
    /// STUN servers handed to apps for discovering their public UDP address.
    pub stun_servers: Vec<String>,
    /// Optional UDP relay (host:port) for when hole punching fails. Railway has no
    /// public UDP, so by default apps fall back to relaying over the WebSocket.
    pub udp_relay: Option<String>,
    /// Allow the relay over WebSocket (TCP) as the last resort.
    pub ws_relay: bool,
    /// Discord app public key (hex, General Information → Public Key): turns on the
    /// `/jugar` bot at `POST /discord/interactions`.
    pub discord_public_key: Option<[u8; 32]>,
    /// Where invites send people who don't have the app yet.
    pub download_url: Option<String>,
}

fn var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing environment variable {name}"))
}

fn b64(name: &str, value: &str) -> Result<Vec<u8>> {
    let v = value.trim();
    base64::engine::general_purpose::STANDARD
        .decode(v)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v))
        .with_context(|| format!("{name} must be base64"))
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let jwt_secret = b64("JWT_SECRET", &var("JWT_SECRET")?)?;
        if jwt_secret.len() < 32 {
            bail!("JWT_SECRET must be at least 32 bytes (generate with: openssl rand -base64 48)");
        }
        let seed = b64("TICKET_SIGNING_KEY", &var("TICKET_SIGNING_KEY")?)?;
        let ticket_seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("TICKET_SIGNING_KEY must be exactly 32 bytes (openssl rand -base64 32)"))?;
        let public_url = var("PUBLIC_URL")?.trim_end_matches('/').to_string();
        Ok(Self {
            database_url: var("DATABASE_URL")?,
            port: std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080),
            public_url,
            discord_client_id: var("DISCORD_CLIENT_ID")?,
            discord_client_secret: var("DISCORD_CLIENT_SECRET")?,
            jwt_secret,
            ticket_seed,
            stun_servers: std::env::var("STUN_SERVERS")
                .unwrap_or_else(|_| "stun.l.google.com:19302,stun.cloudflare.com:3478".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            udp_relay: std::env::var("UDP_RELAY").ok().filter(|s| !s.trim().is_empty()),
            ws_relay: std::env::var("WS_RELAY").map(|v| v != "0" && v != "false").unwrap_or(true),
            discord_public_key: match std::env::var("DISCORD_PUBLIC_KEY").ok().filter(|s| !s.trim().is_empty()) {
                Some(k) => Some(
                    crate::discord_bot::hex32(&k)
                        .context("DISCORD_PUBLIC_KEY must be the 64 hex characters from the Discord app's General Information page")?,
                ),
                None => None,
            },
            download_url: std::env::var("DOWNLOAD_URL").ok().map(|s| s.trim().to_string()).filter(|s| s.starts_with("https://")),
        })
    }

    pub fn discord_redirect_uri(&self) -> String {
        format!("{}/v1/auth/discord/callback", self.public_url)
    }
}
