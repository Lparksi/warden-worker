use std::convert::TryFrom;
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;
use axum::{
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::Response,
};

mod auth;
mod crypto;
mod db;
mod error;
mod handlers;
mod jwt;
mod models;
mod notifications;
mod router;
mod smtp;
mod two_factor;
mod webauthn;

/// Middleware to add security headers to all responses
async fn add_security_headers(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    
    // Prevent MIME type sniffing
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    
    // Prevent clickjacking
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    
    // Enable XSS protection (for older browsers)
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );
    
    // Content Security Policy - restrictive for API, relaxed for web vault
    // Note: Web vault is served as static assets, CSP mainly protects API endpoints
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
    );
    
    // Referrer policy - don't leak origin to external sites
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    
    // Permissions policy - restrict browser features
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    
    response
}

#[event(fetch)]
pub async fn main(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    // Set up logging
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    // Allow all origins for CORS, which is typical for a public API like Bitwarden's.
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    if notifications::is_notifications_path(req.uri().path()) {
        let worker_req = Request::try_from(req)?;
        let worker_resp = notifications::proxy_notifications_request(&env, worker_req).await?;
        return Ok(worker_resp.into());
    }

    let mut app = router::api_router(env)
        .layer(middleware::from_fn(add_security_headers))
        .layer(cors);

    Ok(app.call(req).await?)
}
