use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{query, D1Database, Env};

use crate::{
    auth::Claims,
    db,
    error::AppError,
    jwt,
    models::user::{KeyData, PreloginResponse, RegisterRequest, User},
    smtp::SmtpConfig,
    two_factor, webauthn,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub user_asymmetric_keys: Option<KeyData>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPasswordRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerificationRequest {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterVerificationClaims {
    sub: String,
    email: String,
    name: Option<String>,
    exp: i64,
    nbf: i64,
}

#[worker::send]
pub async fn profile(claims: Claims, State(env): State<Arc<Env>>) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?
        || webauthn::is_webauthn_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn revision_date(_claims: Claims) -> Result<Json<i64>, AppError> {
    Ok(Json(chrono::Utc::now().timestamp_millis()))
}

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&env)?;

    let stmt = db.prepare("SELECT kdf_type, kdf_iterations FROM users WHERE email = ?1");
    let query = stmt.bind(&[email.to_lowercase().into()])?;
    let kdf_row: Option<Value> = query.first(None).await.map_err(|_| AppError::Database)?;
    let kdf = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_type"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);
    let kdf_iterations = kdf_row
        .as_ref()
        .and_then(|row| row.get("kdf_iterations"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(600_000);

    Ok(Json(PreloginResponse {
        kdf,
        kdf_iterations,
        kdf_memory: None,
        kdf_parallelism: None,
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let normalized_email = payload.email.trim().to_lowercase();
    ensure_signup_allowed(env.as_ref(), &db, &normalized_email).await?;
    let now = Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        email: normalized_email,
        email_verified: false,
        master_password_hash: payload.master_password_hash,
        master_password_hint: payload.master_password_hint,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        security_stamp: Uuid::new_v4().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
         user.id,
         user.name,
         user.email,
         user.master_password_hash,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_type,
         user.kdf_iterations,
         user.security_stamp,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_master_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeMasterPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let master_password_hint = payload.master_password_hint.clone();
    let private_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_else(|| user.private_key.clone());
    let public_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_else(|| user.public_key.clone());
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, security_stamp = ?8, updated_at = ?9 WHERE id = ?10",
    )
    .bind(&[
        payload.new_master_password_hash.into(),
        to_js_val(master_password_hint),
        payload.user_symmetric_key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_email(
    headers: HeaderMap,
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.new_email.trim().is_empty() {
        return Err(AppError::BadRequest("Missing newEmail".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let new_email = payload.new_email.to_lowercase();

    let db = db::get_db(&env)?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;
    let old_email = user.email.clone();

    if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);

    db.prepare(
        "UPDATE users SET email = ?1, email_verified = ?2, master_password_hash = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, security_stamp = ?7, updated_at = ?8 WHERE id = ?9",
    )
    .bind(&[
        new_email.clone().into(),
        false.into(),
        payload.new_master_password_hash.into(),
        payload.user_symmetric_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        security_stamp.into(),
        now.into(),
        claims.sub.into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Email already in use".to_string())
        } else {
            AppError::Database
        }
    })?;

    let origin = origin_from_headers(&headers);
    match SmtpConfig::from_env(env.as_ref()) {
        Ok(Some(smtp)) => {
            if let Err(err) = smtp
                .send_change_email_confirmation(&new_email, &old_email, &origin)
                .await
            {
                log::warn!("send change email confirmation failed: {err}");
            }
            if let Err(err) = smtp
                .send_change_email_alert(&old_email, &new_email, &origin)
                .await
            {
                log::warn!("send change email alert failed: {err}");
            }
        }
        Ok(None) => {}
        Err(err) => log::warn!("smtp config invalid, skip change email notifications: {err}"),
    }

    Ok(Json(json!({})))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

#[worker::send]
pub async fn send_verification_email(
    headers: HeaderMap,
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterVerificationRequest>,
) -> Result<String, AppError> {
    let normalized_email = payload.email.trim().to_lowercase();
    if normalized_email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }

    let db = db::get_db(&env)?;
    ensure_signup_allowed(env.as_ref(), &db, &normalized_email).await?;

    let now = Utc::now().timestamp();
    let claims = RegisterVerificationClaims {
        sub: normalized_email.clone(),
        email: normalized_email.clone(),
        name: payload.name,
        exp: now + 3600,
        nbf: now.saturating_sub(30),
    };
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let token = jwt::encode_hs256(&claims, &jwt_secret)?;

    if let Some(smtp) = SmtpConfig::from_env(env.as_ref())? {
        smtp.send_register_verify_email(&normalized_email, &token, &origin_from_headers(&headers))
            .await?;
    }

    Ok(token)
}

#[worker::send]
pub async fn verify_password(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<VerifyPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }

    let db = db::get_db(&env)?;
    let stored_hash: Option<String> = db
        .prepare("SELECT master_password_hash FROM users WHERE id = ?1")
        .bind(&[claims.sub.into()])?
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

    Ok(Json(Value::Null))
}

async fn ensure_signup_allowed(
    env: &Env,
    db: &D1Database,
    normalized_email: &str,
) -> Result<(), AppError> {
    let user_count: Option<i64> = db
        .prepare("SELECT COUNT(1) AS user_count FROM users")
        .first(Some("user_count"))
        .await
        .map_err(|_| AppError::Database)?;
    let user_count = user_count.unwrap_or(0);
    if user_count > 0 {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }

    let allowed_emails = env
        .secret("ALLOWED_EMAILS")
        .ok()
        .and_then(|secret| secret.as_ref().as_string())
        .unwrap_or_default();
    if !allowed_emails.trim().is_empty()
        && allowed_emails
            .split(",")
            .map(|email| email.trim().to_lowercase())
            .all(|email| email != normalized_email)
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }

    Ok(())
}

fn origin_from_headers(headers: &HeaderMap) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .or_else(|| headers.get("X-Forwarded-Proto"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("https");
    let host = headers
        .get("host")
        .or_else(|| headers.get("Host"))
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}
