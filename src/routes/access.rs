//! Connection code + password per device, made by the server.
//!
//! The code (9 random digits) is stable; the password is random until the user sets
//! their own. Only an argon2id hash of the password is stored. Anyone signed in who has
//! both can connect from anywhere: the hub checks them and sets up the peer-to-peer
//! connection (see `hub.rs`, `connect_code`).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::Json;
use axum::extract::State;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult, bad};

/// Unambiguous characters for generated passwords (no 0/o, 1/l/i).
const PW_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const PW_LEN: usize = 8;

pub fn random_password() -> String {
    let mut r = rand::thread_rng();
    (0..PW_LEN).map(|_| PW_ALPHABET[r.gen_range(0..PW_ALPHABET.len())] as char).collect()
}

fn random_code() -> String {
    let mut r = rand::thread_rng();
    // First digit 1–9 so it never looks shorter when read aloud.
    format!("{}{:08}", r.gen_range(1..10), r.gen_range(0..100_000_000u32))
}

pub async fn hash(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2::Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|e| ApiError::Internal(e.into()))?
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("hash: {e}")))
}

pub async fn verify(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).is_ok_and(|h| argon2::Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
    })
    .await
    .unwrap_or(false)
}

/// Only digits (spaces and dashes are allowed when typing).
pub fn normalize_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (digits.len() == 9 && digits.chars().all(|c| c.is_ascii_digit())).then_some(digits)
}

#[derive(Serialize)]
pub struct Access {
    pub code: String,
    /// Only returned when the server just made it (it keeps a hash only).
    pub password: Option<String>,
    pub custom_password: bool,
}

fn this_device(user: &AuthUser) -> ApiResult<Uuid> {
    user.device_id.ok_or_else(|| bad("no_device", "This sign-in has no device"))
}

/// The code of the calling device (404 if it has none yet).
pub async fn get(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Access>> {
    let device = this_device(&user)?;
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT code::text, custom_password FROM device_access WHERE device_id = $1")
            .bind(device)
            .fetch_optional(&state.db)
            .await?;
    let (code, custom_password) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(Access { code, password: None, custom_password }))
}

/// New random password (and a code, the first time). Returns the password once.
pub async fn rotate(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Access>> {
    let device = this_device(&user)?;
    let password = random_password();
    let h = hash(password.clone()).await?;
    let code = upsert(&state, user.user_id, device, &h, false).await?;
    Ok(Json(Access { code, password: Some(password), custom_password: false }))
}

#[derive(Deserialize)]
pub struct SetPassword {
    pub password: String,
}

/// The user's own password (kept until changed).
pub async fn set_password(State(state): State<AppState>, user: AuthUser, Json(b): Json<SetPassword>) -> ApiResult<Json<Access>> {
    let device = this_device(&user)?;
    let pw = b.password.trim().to_string();
    if pw.chars().count() < 6 || pw.len() > 64 {
        return Err(bad("weak_password", "Use 6 to 64 characters"));
    }
    let h = hash(pw).await?;
    let code = upsert(&state, user.user_id, device, &h, true).await?;
    Ok(Json(Access { code, password: None, custom_password: true }))
}

/// Saves the password hash, creating the device's code if it has none.
async fn upsert(state: &AppState, user: Uuid, device: Uuid, h: &str, custom: bool) -> ApiResult<String> {
    for _ in 0..20 {
        let r: Result<String, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO device_access (device_id, user_id, code, password_hash, custom_password)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (device_id) DO UPDATE SET password_hash = EXCLUDED.password_hash,
                custom_password = EXCLUDED.custom_password, failed_attempts = 0, locked_until = NULL
             RETURNING code::text",
        )
        .bind(device)
        .bind(user)
        .bind(random_code())
        .bind(h)
        .bind(custom)
        .fetch_one(&state.db)
        .await;
        match r {
            Ok(code) => return Ok(code),
            // Code collision with another device: try another one.
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("device_access_code_key") => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Internal(anyhow::anyhow!("couldn't find a free code")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_passwords() {
        for _ in 0..1000 {
            let c = random_code();
            assert_eq!(c.len(), 9);
            assert!(!c.starts_with('0'));
            assert_eq!(normalize_code(&format!("{} {} {}", &c[..3], &c[3..6], &c[6..])), Some(c));
        }
        assert_eq!(normalize_code("12345678"), None);
        assert_eq!(normalize_code("12345678a"), None);
        let p = random_password();
        assert_eq!(p.len(), PW_LEN);
        assert!(p.bytes().all(|b| PW_ALPHABET.contains(&b)));
    }
}
