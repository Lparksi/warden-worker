use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use js_sys::Date;
use rand::rngs::OsRng;
use rand::RngCore;
use totp_rs::{Algorithm, Secret, TOTP};
use worker::D1Database;

use crate::error::AppError;

pub const TWO_FACTOR_PROVIDER_AUTHENTICATOR: i32 = 0;
pub const TWO_FACTOR_PROVIDER_EMAIL: i32 = 1;

#[derive(Debug, Clone)]
pub struct EmailTwoFactorState {
    pub enabled: bool,
    pub email: String,
    pub last_token: Option<String>,
    pub token_sent: Option<i64>,
    pub attempts: i64,
}

pub fn generate_totp_secret_base32_20() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    Secret::Raw(bytes.to_vec()).to_encoded().to_string()
}

pub fn generate_email_token(token_size: usize) -> String {
    let size = token_size.clamp(6, 16);
    let mut out = String::with_capacity(size);
    for _ in 0..size {
        let n = (OsRng.next_u32() % 10) as u8;
        out.push((b'0' + n) as char);
    }
    out
}

pub async fn ensure_two_factor_authenticator_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_authenticator (
            user_id TEXT PRIMARY KEY NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            secret_enc TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn ensure_two_factor_email_table(db: &D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS two_factor_email (
            user_id TEXT PRIMARY KEY NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 0,
            email TEXT NOT NULL,
            last_token TEXT,
            token_sent INTEGER,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn is_authenticator_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let enabled: Option<i64> = db
        .prepare("SELECT enabled FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(matches!(enabled, Some(1)))
}

pub async fn is_email_enabled(db: &D1Database, user_id: &str) -> Result<bool, AppError> {
    ensure_two_factor_email_table(db).await?;
    let enabled: Option<i64> = db
        .prepare("SELECT enabled FROM two_factor_email WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(matches!(enabled, Some(1)))
}

pub async fn get_authenticator_secret_enc(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    let secret_enc: Option<String> = db
        .prepare("SELECT secret_enc FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .first(Some("secret_enc"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(secret_enc)
}

pub async fn get_email_state(
    db: &D1Database,
    user_id: &str,
) -> Result<Option<EmailTwoFactorState>, AppError> {
    ensure_two_factor_email_table(db).await?;
    let row: Option<serde_json::Value> = db
        .prepare(
            "SELECT enabled, email, last_token, token_sent, attempts
             FROM two_factor_email
             WHERE user_id = ?1",
        )
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Ok(None);
    };

    let enabled = row
        .get("enabled")
        .and_then(|v| v.as_i64())
        .map(|v| v == 1)
        .unwrap_or(false);
    let email = row
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let last_token = row
        .get("last_token")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let token_sent = row.get("token_sent").and_then(|v| v.as_i64());
    let attempts = row.get("attempts").and_then(|v| v.as_i64()).unwrap_or(0);

    Ok(Some(EmailTwoFactorState {
        enabled,
        email,
        last_token,
        token_sent,
        attempts,
    }))
}

pub async fn upsert_authenticator_secret(
    db: &D1Database,
    user_id: &str,
    secret_enc: String,
    enabled: bool,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_authenticator (user_id, enabled, secret_enc, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET enabled = excluded.enabled, secret_enc = excluded.secret_enc, updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        (if enabled { 1 } else { 0 }).into(),
        secret_enc.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn upsert_email_state(
    db: &D1Database,
    user_id: &str,
    enabled: bool,
    email: &str,
    now: &str,
) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    db.prepare(
        "INSERT INTO two_factor_email (user_id, enabled, email, last_token, token_sent, attempts, created_at, updated_at)
         VALUES (?1, ?2, ?3, NULL, NULL, 0, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET
           enabled = excluded.enabled,
           email = excluded.email,
           updated_at = excluded.updated_at",
    )
    .bind(&[
        user_id.into(),
        (if enabled { 1 } else { 0 }).into(),
        email.into(),
        now.into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn set_email_token(
    db: &D1Database,
    user_id: &str,
    token: &str,
    now_rfc3339: &str,
) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    let ts = Utc::now().timestamp() as f64;
    db.prepare(
        "UPDATE two_factor_email
         SET last_token = ?1, token_sent = ?2, attempts = 0, updated_at = ?3
         WHERE user_id = ?4",
    )
    .bind(&[token.into(), ts.into(), now_rfc3339.into(), user_id.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn consume_email_token(
    db: &D1Database,
    user_id: &str,
    token: &str,
    expiration_secs: i64,
    attempts_limit: i64,
) -> Result<(), AppError> {
    let state = get_email_state(db, user_id).await?;
    let Some(state) = state else {
        return Err(AppError::Unauthorized(
            "Invalid two factor token.".to_string(),
        ));
    };
    let Some(issued_token) = state.last_token.as_deref() else {
        return Err(AppError::Unauthorized(
            "Invalid two factor token.".to_string(),
        ));
    };
    let Some(sent_ts) = state.token_sent else {
        return Err(AppError::Unauthorized(
            "Invalid two factor token.".to_string(),
        ));
    };

    let now_ts = Utc::now().timestamp();
    if now_ts > sent_ts.saturating_add(expiration_secs.max(1)) {
        clear_email_token(db, user_id).await?;
        return Err(AppError::Unauthorized(
            "Invalid two factor token.".to_string(),
        ));
    }

    if !constant_time_eq::constant_time_eq(issued_token.as_bytes(), token.as_bytes()) {
        bump_email_attempt(db, user_id).await?;
        let refreshed = get_email_state(db, user_id).await?;
        if let Some(refreshed) = refreshed {
            if refreshed.attempts >= attempts_limit.max(1) {
                clear_email_token(db, user_id).await?;
            }
        }
        return Err(AppError::Unauthorized(
            "Invalid two factor token.".to_string(),
        ));
    }

    clear_email_token(db, user_id).await?;
    Ok(())
}

pub async fn clear_email_token(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    let now = Utc::now().to_rfc3339();
    db.prepare(
        "UPDATE two_factor_email
         SET last_token = NULL, token_sent = NULL, attempts = 0, updated_at = ?1
         WHERE user_id = ?2",
    )
    .bind(&[now.into(), user_id.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn bump_email_attempt(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    let now = Utc::now().to_rfc3339();
    db.prepare(
        "UPDATE two_factor_email
         SET attempts = COALESCE(attempts, 0) + 1, updated_at = ?1
         WHERE user_id = ?2",
    )
    .bind(&[now.into(), user_id.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn disable_authenticator(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_authenticator_table(db).await?;
    db.prepare("DELETE FROM two_factor_authenticator WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn disable_email(db: &D1Database, user_id: &str) -> Result<(), AppError> {
    ensure_two_factor_email_table(db).await?;
    db.prepare("DELETE FROM two_factor_email WHERE user_id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

pub fn obscure_email(email: &str) -> String {
    let mut parts = email.rsplitn(2, '@');
    let domain = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if name.is_empty() || domain.is_empty() {
        return "***".to_string();
    }

    let mut name_chars = name.chars();
    let first = name_chars.next().unwrap_or('*');
    let second = name_chars.next().unwrap_or('*');
    let rest_len = name_chars.count();
    let stars = if rest_len == 0 { 1 } else { rest_len };
    format!("{first}{second}{}@{domain}", "*".repeat(stars))
}

pub fn encrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_encoded: &str,
) -> Result<String, AppError> {
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Ok(format!("plain:{}", secret_encoded));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "Invalid TWO_FACTOR_ENC_KEY".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret_encoded.as_bytes(),
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(format!("gcm:{}", general_purpose::STANDARD.encode(blob)))
}

pub fn decrypt_secret_with_optional_key(
    two_factor_enc_key_b64: Option<&str>,
    user_id: &str,
    secret_enc: &str,
) -> Result<String, AppError> {
    if let Some(rest) = secret_enc.strip_prefix("plain:") {
        return Ok(rest.to_string());
    }
    let Some(rest) = secret_enc.strip_prefix("gcm:") else {
        return Err(AppError::Internal);
    };
    let Some(key_b64) = two_factor_enc_key_b64 else {
        return Err(AppError::BadRequest(
            "Missing TWO_FACTOR_ENC_KEY".to_string(),
        ));
    };

    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::BadRequest("Invalid TWO_FACTOR_ENC_KEY".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "Invalid TWO_FACTOR_ENC_KEY".to_string(),
        ));
    }

    let blob = general_purpose::STANDARD
        .decode(rest)
        .map_err(|_| AppError::Internal)?;
    if blob.len() < 12 {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| {
            AppError::BadRequest(
                "Two-factor secret cannot be decrypted. Please regenerate the secret.".to_string(),
            )
        })?;

    String::from_utf8(pt).map_err(|_| AppError::Internal)
}

pub fn verify_totp_code(secret_encoded: &str, token: &str) -> Result<bool, AppError> {
    let token = token.trim();
    if token.len() != 6 || !token.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }

    let secret = Secret::Encoded(secret_encoded.to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| AppError::Internal)?,
        None,
        "".to_string(),
    )
    .map_err(|_| AppError::Internal)?;
    let unix_seconds = (Date::now() / 1000.0).floor() as u64;
    Ok(totp.check(token, unix_seconds))
}

#[cfg(test)]
mod tests {
    use super::generate_totp_secret_base32_20;
    use totp_rs::Secret;

    #[test]
    fn generated_totp_secret_is_20_bytes() {
        let secret = generate_totp_secret_base32_20();
        let bytes = Secret::Encoded(secret).to_bytes().expect("decode base32");
        assert_eq!(bytes.len(), 20);
    }
}
