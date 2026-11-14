//! The Discord bot: `/jugar` (`/play` in English Discord) invites friends to play on
//! your PC, from any server, DM or group DM.
//!
//! It's an HTTP interactions endpoint (`POST /discord/interactions`): Discord calls it
//! for each command, signed with the app's Ed25519 key, so no gateway connection or
//! bot token is needed. The command is installable on a server *and* on a user's own
//! account (`integration_types` 0 and 1), so it works in DMs with friends too.
//!
//! `/jugar @Luis @Pedro` makes one invite per friend that only their Discord account
//! can use (they go straight in). `/jugar` alone makes an open invite: anyone signed in
//! can use it, and the host approves each one in the app.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::AppState;
use crate::routes::invites::{self, NewInvite, Source};

/// Invites from the command live this long.
const INVITE_TTL_SECS: i64 = 30 * 60;
/// An open invite works for this many people.
const OPEN_INVITE_USES: i32 = 8;
/// Friend options on the command (`amigo`, `amigo2`…).
const FRIEND_OPTIONS: usize = 4;
const EPHEMERAL: u64 = 1 << 6;

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex64(s: &str) -> Option<[u8; 64]> {
    let s = s.trim();
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Discord signs `timestamp + body`; anything else must be rejected with 401.
pub fn verify(public_key: &[u8; 32], headers: &HeaderMap, body: &[u8]) -> bool {
    let get = |h: &str| headers.get(h).and_then(|v| v.to_str().ok());
    let (Some(sig), Some(ts)) = (get("x-signature-ed25519"), get("x-signature-timestamp")) else { return false };
    let (Some(sig), Ok(key)) = (hex64(sig), VerifyingKey::from_bytes(public_key)) else { return false };
    let mut msg = Vec::with_capacity(ts.len() + body.len());
    msg.extend_from_slice(ts.as_bytes());
    msg.extend_from_slice(body);
    key.verify_strict(&msg, &Signature::from_bytes(&sig)).is_ok()
}

/// `POST /discord/interactions`
pub async fn interactions(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(key) = state.cfg.discord_public_key else {
        return (StatusCode::NOT_FOUND, "bot not configured").into_response();
    };
    if !verify(&key, &headers, &body) {
        return (StatusCode::UNAUTHORIZED, "invalid request signature").into_response();
    }
    let Ok(i) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    match i["type"].as_u64() {
        // PING (Discord checks the endpoint when you save it).
        Some(1) => Json(json!({ "type": 1 })).into_response(),
        Some(2) => {
            let reply = match command(&state, &i).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("discord command: {e:#}");
                    let es = lang_es(&i);
                    ephemeral(if es { "Algo falló de nuestro lado. Inténtalo otra vez." } else { "Something went wrong on our side. Try again." })
                }
            };
            Json(reply).into_response()
        }
        _ => Json(ephemeral("?")).into_response(),
    }
}

fn lang_es(i: &Value) -> bool {
    // The channel's language when there is one (others read the message), else the user's.
    let l = i["guild_locale"].as_str().or(i["locale"].as_str()).unwrap_or("en");
    l.starts_with("es")
}

fn ephemeral(text: &str) -> Value {
    json!({ "type": 4, "data": { "content": text, "flags": EPHEMERAL, "allowed_mentions": { "parse": [] } } })
}

fn download_row(state: &AppState, es: bool) -> Option<Value> {
    state.cfg.download_url.as_ref().map(|u| {
        json!({ "type": 1, "components": [{ "type": 2, "style": 5, "label": if es { "Descargar Distanplay" } else { "Download Distanplay" }, "url": u }] })
    })
}

/// A Discord user's name to show (global display name, else username).
fn name_of(u: &Value) -> String {
    u["global_name"].as_str().filter(|s| !s.is_empty()).or(u["username"].as_str()).unwrap_or("?").to_string()
}

async fn command(state: &AppState, i: &Value) -> anyhow::Result<Value> {
    let es = lang_es(i);
    let t = |a: &'static str, b: &'static str| if es { a } else { b };
    let data = &i["data"];
    if !matches!(data["name"].as_str(), Some("jugar")) {
        return Ok(ephemeral(t("No conozco ese comando.", "I don't know that command.")));
    }
    // In a server the caller is `member.user`; in DMs / user installs it's `user`.
    let caller = if i["member"]["user"].is_object() { &i["member"]["user"] } else { &i["user"] };
    let Some(caller_id) = caller["id"].as_str() else { return Ok(ephemeral("?")) };

    let host: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.display_name FROM user_identities ui JOIN users u ON u.id = ui.user_id
         WHERE ui.provider = 'discord' AND ui.provider_user_id = $1 AND u.status = 'active'",
    )
    .bind(caller_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((host_user, host_name)) = host else {
        let mut r = ephemeral(t(
            "Para invitar, primero instala Distanplay e inicia sesión con Discord en la PC que quieres compartir.",
            "To invite friends, first install Distanplay and sign in with Discord on the PC you want to share.",
        ));
        if let Some(row) = download_row(state, es) {
            r["data"]["components"] = json!([row]);
        }
        return Ok(r);
    };

    // The PC to share: the caller's device that's online now (most recently seen first).
    let online = state.hub.online_devices(host_user);
    let device: Option<Uuid> = if online.is_empty() {
        None
    } else {
        sqlx::query_scalar("SELECT id FROM devices WHERE id = ANY($1) AND revoked_at IS NULL ORDER BY last_seen_at DESC NULLS LAST LIMIT 1")
            .bind(&online)
            .fetch_optional(&state.db)
            .await?
    };
    let Some(host_device) = device else {
        return Ok(ephemeral(t(
            "Abre Distanplay en la PC que quieres compartir (con la sesión iniciada) y vuelve a usar /jugar.",
            "Open Distanplay on the PC you want to share (signed in) and use /play again.",
        )));
    };

    // Named friends (the bot and the caller themself are skipped).
    let mut friends: Vec<(String, String)> = Vec::new();
    let mut message: Option<String> = None;
    for opt in data["options"].as_array().into_iter().flatten() {
        let name = opt["name"].as_str().unwrap_or_default();
        if name == "mensaje" {
            message = opt["value"].as_str().map(|s| s.trim().chars().take(100).collect()).filter(|s: &String| !s.is_empty());
            continue;
        }
        let Some(id) = opt["value"].as_str() else { continue };
        let u = &data["resolved"]["users"][id];
        if id == caller_id || u["bot"].as_bool() == Some(true) || friends.iter().any(|(f, _)| f == id) {
            continue;
        }
        friends.push((id.to_string(), name_of(u)));
        if friends.len() >= FRIEND_OPTIONS {
            break;
        }
    }

    let mut buttons = Vec::new();
    let host_md = escape_md(&host_name);
    let mut content = if friends.is_empty() {
        for_open(&host_md, es)
    } else {
        let mentions: Vec<String> = friends.iter().map(|(id, _)| format!("<@{id}>")).collect();
        format!("🎮 **{host_md}** {} {}", t("te invita a jugar en su PC:", "invited you to play on their PC:"), mentions.join(" "))
    };
    if friends.is_empty() {
        let (_, token) = invites::create(
            state,
            NewInvite { host_user, host_device, for_discord: None, source: Source::Discord, max_uses: OPEN_INVITE_USES, ttl_secs: INVITE_TTL_SECS },
        )
        .await?;
        buttons.push(json!({ "type": 2, "style": 5, "label": t("Unirse", "Join"), "url": invites::url(state, &token) }));
    } else {
        for (id, name) in &friends {
            let (_, token) = invites::create(
                state,
                NewInvite {
                    host_user,
                    host_device,
                    for_discord: Some((id, name)),
                    source: Source::Discord,
                    max_uses: 1,
                    ttl_secs: INVITE_TTL_SECS,
                },
            )
            .await?;
            let label: String = format!("{} · {name}", t("Unirse", "Join")).chars().take(80).collect();
            buttons.push(json!({ "type": 2, "style": 5, "label": label, "url": invites::url(state, &token) }));
        }
    }
    if let Some(m) = message {
        content.push_str(&format!("\n> {}", escape_md(&m)));
    }
    content.push_str(t("\n-# Caduca en 30 minutos.", "\n-# Expires in 30 minutes."));
    let mut rows = vec![json!({ "type": 1, "components": buttons })];
    if let Some(row) = download_row(state, es) {
        rows.push(row);
    }
    tracing::info!("/jugar from {host_user}: {} named friend(s)", friends.len());
    Ok(json!({
        "type": 4,
        "data": {
            "content": content,
            "components": rows,
            "allowed_mentions": { "users": friends.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>() },
        }
    }))
}

fn for_open(host_md: &str, es: bool) -> String {
    if es {
        format!("🎮 **{host_md}** está compartiendo su PC. ¿Quién se une? (Acepta a cada uno desde su PC.)")
    } else {
        format!("🎮 **{host_md}** is sharing their PC. Who's joining? (They let each person in.)")
    }
}

/// Keeps names from turning into markdown or mentions.
fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '_' | '~' | '`' | '|' | '>' | '#' | '[' | ']' | '(' | ')' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.replace('@', "@\u{200B}")
}

/// The command definition (registered on start with the app's client credentials).
fn commands() -> Value {
    let mut options = Vec::new();
    for n in 0..FRIEND_OPTIONS {
        let (name, en) = if n == 0 { ("amigo".to_string(), "friend".to_string()) } else { (format!("amigo{}", n + 1), format!("friend{}", n + 1)) };
        options.push(json!({
            "type": 6, "name": name, "name_localizations": { "en-US": en, "en-GB": en },
            "description": "A quién invitas (entra directo)",
            "description_localizations": { "en-US": "Who to invite (they go straight in)", "en-GB": "Who to invite (they go straight in)" },
            "required": false,
        }));
    }
    options.push(json!({
        "type": 3, "name": "mensaje", "name_localizations": { "en-US": "message", "en-GB": "message" },
        "description": "Un mensaje corto (p. ej. \"Tekken, ¿quién juega?\")",
        "description_localizations": { "en-US": "A short message (e.g. \"Tekken, who's in?\")", "en-GB": "A short message" },
        "required": false, "max_length": 100,
    }));
    json!([{
        "name": "jugar",
        "name_localizations": { "en-US": "play", "en-GB": "play" },
        "description": "Invita a tus amigos a jugar en tu PC con Distanplay",
        "description_localizations": { "en-US": "Invite friends to play on your PC with Distanplay", "en-GB": "Invite friends to play on your PC with Distanplay" },
        "type": 1,
        // Server installs and user installs; usable in servers, the bot's DM, and any DM / group DM.
        "integration_types": [0, 1],
        "contexts": [0, 1, 2],
        "options": options,
    }])
}

/// Registers `/jugar` with Discord (idempotent bulk overwrite). Uses the client
/// credentials grant, so no bot token is needed.
pub async fn register_commands(state: AppState) {
    if state.cfg.discord_public_key.is_none() || std::env::var("DISCORD_REGISTER_COMMANDS").as_deref() == Ok("0") {
        return;
    }
    let r: anyhow::Result<()> = async {
        let tok: Value = state
            .http
            .post("https://discord.com/api/v10/oauth2/token")
            .basic_auth(&state.cfg.discord_client_id, Some(&state.cfg.discord_client_secret))
            .form(&[("grant_type", "client_credentials"), ("scope", "applications.commands.update")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let access = tok["access_token"].as_str().ok_or_else(|| anyhow::anyhow!("no access_token"))?;
        let url = format!("https://discord.com/api/v10/applications/{}/commands", state.cfg.discord_client_id);
        let resp = state.http.put(url).bearer_auth(access).json(&commands()).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("{status}: {}", resp.text().await.unwrap_or_default());
        }
        Ok(())
    }
    .await;
    match r {
        Ok(()) => tracing::info!("Discord: /jugar command registered"),
        Err(e) => tracing::warn!("Discord: couldn't register /jugar: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signature_check() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let body = br#"{"type":1}"#;
        let ts = "1700000000";
        let mut msg = ts.as_bytes().to_vec();
        msg.extend_from_slice(body);
        let sig: String = sk.sign(&msg).to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let mut h = HeaderMap::new();
        h.insert("x-signature-ed25519", sig.parse().unwrap());
        h.insert("x-signature-timestamp", ts.parse().unwrap());
        assert!(verify(&pk, &h, body));
        assert!(!verify(&pk, &h, br#"{"type":2}"#), "tampered body");
        h.insert("x-signature-timestamp", "1700000001".parse().unwrap());
        assert!(!verify(&pk, &h, body), "other timestamp");
        assert!(!verify(&pk, &HeaderMap::new(), body), "no headers");
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex32(&hex), Some(pk));
        assert_eq!(hex32("zz"), None);
    }

    #[test]
    fn markdown_and_command_shape() {
        assert_eq!(escape_md("a*b_@everyone"), "a\\*b\\_@\u{200B}everyone");
        let c = commands();
        assert_eq!(c[0]["name"], "jugar");
        assert_eq!(c[0]["options"].as_array().unwrap().len(), FRIEND_OPTIONS + 1);
        assert_eq!(c[0]["integration_types"], json!([0, 1]));
    }
}
