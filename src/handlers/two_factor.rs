use axum::{extract::State, Json};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use worker::Env;

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::smtp::SmtpConfig;
use crate::two_factor;
use crate::webauthn;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpData {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

impl PasswordOrOtpData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                let stored_hash: Option<String> = db
                    .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
                    .bind(&[user_id.into()])?
                    .first(Some("master_password_hash"))
                    .await
                    .map_err(|_| AppError::Database)?;
                let Some(stored_hash) = stored_hash else {
                    return Err(AppError::NotFound("User not found".to_string()));
                };
                if !constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes()) {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(_)) => Err(AppError::BadRequest(
                "OTP validation is not supported".to_string(),
            )),
            _ => Err(AppError::BadRequest("No validation provided".to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    key: String,
    token: NumberOrString,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    key: String,
    master_password_hash: String,
    #[serde(rename = "type")]
    r#type: NumberOrString,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorProviderData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    #[serde(rename = "type")]
    r#type: NumberOrString,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailData {
    email: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailData {
    token: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailLoginData {
    email: String,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
}

#[worker::send]
pub async fn two_factor_status(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let email_enabled = two_factor::is_email_enabled(&db, &claims.sub).await?;
    let webauthn_enabled = webauthn::is_webauthn_enabled(&db, &claims.sub).await?;
    let enabled = authenticator_enabled || email_enabled || webauthn_enabled;
    let mut providers: Vec<i32> = Vec::new();
    if authenticator_enabled {
        providers.push(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR);
    }
    if email_enabled {
        providers.push(two_factor::TWO_FACTOR_PROVIDER_EMAIL);
    }
    if webauthn_enabled {
        providers.push(webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN);
    }
    Ok(Json(json!({
        "enabled": enabled,
        "providers": providers
    })))
}

#[worker::send]
pub async fn authenticator_request(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_email = user_email.ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let secret_encoded = two_factor::generate_totp_secret_base32_20();
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_encoded,
    )?;

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, false, &now).await?;

    let issuer = env
        .var("TWO_FACTOR_ISSUER")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "Warden Worker".to_string());
    let issuer = issuer.replace(':', "");
    let account = user_email.replace(':', "");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_encoded.clone())
            .to_bytes()
            .map_err(|_| AppError::Internal)?,
        Some(issuer.clone()),
        account.clone(),
    )
    .map_err(|_| AppError::Internal)?;
    let otpauth = totp.get_url();
    let qr_base64 = totp.get_qr_base64().map_err(|_| AppError::Internal)?;

    Ok(Json(json!({
        "secret": secret_encoded,
        "otpauth": otpauth,
        "qrBase64": qr_base64
    })))
}

#[worker::send]
pub async fn get_authenticator(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let key = if enabled {
        let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
            .await?
            .ok_or_else(|| AppError::Internal)?;
        let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        two_factor::decrypt_secret_with_optional_key(
            two_factor_key_b64.as_deref(),
            &claims.sub,
            &secret_enc,
        )?
    } else {
        two_factor::generate_totp_secret_base32_20()
    };

    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn get_email(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    payload.validate(&db, &claims.sub).await?;

    let state = two_factor::get_email_state(&db, &claims.sub).await?;
    let (enabled, email) = match state {
        Some(s) if s.enabled => (true, json!(s.email)),
        _ => (false, serde_json::Value::Null),
    };

    Ok(Json(json!({
        "email": email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

#[worker::send]
pub async fn send_email(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<SendEmailData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }

    let smtp = SmtpConfig::from_env(env.as_ref())?
        .ok_or_else(|| AppError::BadRequest("SMTP is not configured".to_string()))?;
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_email_state(&db, &claims.sub, false, &email, &now).await?;

    let token_size = env
        .var("EMAIL_TOKEN_SIZE")
        .ok()
        .and_then(|v| v.to_string().parse::<usize>().ok())
        .unwrap_or(6);
    let token = two_factor::generate_email_token(token_size);
    two_factor::set_email_token(&db, &claims.sub, &token, &now).await?;
    smtp.send_twofactor_email_token(&email, &token).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn email(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<VerifyEmailData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    let token = payload.token.trim().to_string();
    if token.is_empty() {
        return Err(AppError::BadRequest("Missing token".to_string()));
    }

    let expiration = env
        .var("EMAIL_EXPIRATION_TIME")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(600);
    let attempts_limit = env
        .var("EMAIL_ATTEMPTS_LIMIT")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(3);
    two_factor::consume_email_token(&db, &claims.sub, &token, expiration, attempts_limit).await?;

    let state = two_factor::get_email_state(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Email two factor setup not found".to_string()))?;
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_email_state(&db, &claims.sub, true, &state.email, &now).await?;

    Ok(Json(json!({
        "email": state.email,
        "enabled": true,
        "object": "twoFactorEmail"
    })))
}

#[worker::send]
pub async fn send_email_login(
    State(env): State<Arc<Env>>,
    Json(payload): Json<SendEmailLoginData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }

    let user: serde_json::Value = db
        .prepare("SELECT id, master_password_hash FROM users WHERE email = ?1")
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| {
            AppError::Unauthorized("Username or password is incorrect. Try again.".to_string())
        })?
        .ok_or_else(|| {
            AppError::Unauthorized("Username or password is incorrect. Try again.".to_string())
        })?;
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal)?
        .to_string();
    let stored_hash = user
        .get("master_password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal)?
        .to_string();

    let submitted_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("No password hash has been submitted.".to_string()))?;
    if !constant_time_eq(stored_hash.as_bytes(), submitted_hash.as_bytes()) {
        return Err(AppError::Unauthorized(
            "Username or password is incorrect. Try again.".to_string(),
        ));
    }

    let state = two_factor::get_email_state(&db, &user_id).await?;
    let Some(state) = state else {
        return Err(AppError::Unauthorized(
            "Email 2FA is not enabled".to_string(),
        ));
    };
    if !state.enabled {
        return Err(AppError::Unauthorized(
            "Email 2FA is not enabled".to_string(),
        ));
    }

    let smtp = SmtpConfig::from_env(env.as_ref())?
        .ok_or_else(|| AppError::BadRequest("SMTP is not configured".to_string()))?;
    let now = Utc::now().to_rfc3339();
    let token_size = env
        .var("EMAIL_TOKEN_SIZE")
        .ok()
        .and_then(|v| v.to_string().parse::<usize>().ok())
        .unwrap_or(6);
    let token = two_factor::generate_email_token(token_size);
    two_factor::set_email_token(&db, &user_id, &token, &now).await?;
    smtp.send_twofactor_email_token(&state.email, &token)
        .await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn activate_authenticator(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;

    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    let key = payload.key.trim().to_uppercase();
    let key_bytes = Secret::Encoded(key.clone())
        .to_bytes()
        .map_err(|_| AppError::BadRequest("Invalid totp secret".to_string()))?;
    if key_bytes.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    let token = payload.token.into_string();
    if !two_factor::verify_totp_code(&key, &token)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_enc = two_factor::encrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &key,
    )?;
    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;

    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[worker::send]
pub async fn activate_authenticator_put(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    activate_authenticator(claims, State(env), Json(payload)).await
}

#[worker::send]
pub async fn disable_authenticator_vw(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DisableAuthenticatorData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;

    let stored_hash: Option<String> = db
        .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("master_password_hash"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(stored_hash) = stored_hash else {
        return Err(AppError::NotFound("User not found".to_string()));
    };
    if !constant_time_eq(
        stored_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    if let Some(secret_enc) = two_factor::get_authenticator_secret_enc(&db, &claims.sub).await? {
        let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
        let secret_encoded = two_factor::decrypt_secret_with_optional_key(
            two_factor_key_b64.as_deref(),
            &claims.sub,
            &secret_enc,
        )?;
        if secret_encoded.eq_ignore_ascii_case(payload.key.trim()) {
            two_factor::disable_authenticator(&db, &claims.sub).await?;
        } else {
            return Err(AppError::BadRequest(
                "TOTP key does not match recorded value".to_string(),
            ));
        }
    }

    let type_ = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s
            .parse::<i32>()
            .unwrap_or(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR),
    };

    Ok(Json(json!({
        "enabled": false,
        "keys": type_,
        "object": "twoFactorProvider"
    })))
}

#[worker::send]
pub async fn authenticator_enable(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<EnableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();

    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("No pending authenticator setup".to_string()))?;
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = match two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = two_factor::disable_authenticator(&db, &claims.sub).await;
            return Err(e);
        }
    };
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::upsert_authenticator_secret(&db, &claims.sub, secret_enc, true, &now).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn authenticator_disable(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DisableAuthenticatorRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::BadRequest("Authenticator not enabled".to_string()))?;
    let two_factor_key_b64 = env.secret("TWO_FACTOR_ENC_KEY").ok().map(|s| s.to_string());
    let secret_encoded = two_factor::decrypt_secret_with_optional_key(
        two_factor_key_b64.as_deref(),
        &claims.sub,
        &secret_enc,
    )?;
    if !two_factor::verify_totp_code(&secret_encoded, &payload.code)? {
        return Err(AppError::BadRequest("Invalid TOTP code".to_string()));
    }

    two_factor::disable_authenticator(&db, &claims.sub).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn disable_two_factor(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DisableTwoFactorProviderData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&env)?;
    PasswordOrOtpData {
        master_password_hash: payload.master_password_hash,
        otp: payload.otp,
    }
    .validate(&db, &claims.sub)
    .await?;

    let provider = match payload.r#type {
        NumberOrString::Number(n) => n as i32,
        NumberOrString::String(s) => s
            .parse::<i32>()
            .map_err(|_| AppError::BadRequest("Invalid two factor type".to_string()))?,
    };

    match provider {
        two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR => {
            two_factor::disable_authenticator(&db, &claims.sub).await?
        }
        two_factor::TWO_FACTOR_PROVIDER_EMAIL => {
            two_factor::disable_email(&db, &claims.sub).await?
        }
        webauthn::TWO_FACTOR_PROVIDER_WEBAUTHN => {
            webauthn::disable_webauthn(&db, &claims.sub).await?
        }
        _ => {
            return Err(AppError::BadRequest(
                "Unsupported two factor type".to_string(),
            ))
        }
    }

    Ok(Json(json!({
        "enabled": false,
        "keys": provider,
        "object": "twoFactorProvider"
    })))
}
