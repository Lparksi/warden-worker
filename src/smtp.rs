use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;
use worker::{Env, SecureTransport, Socket};

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpSecurity {
    Off,
    StartTls,
    ForceTls,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    host: String,
    port: u16,
    security: SmtpSecurity,
    helo_name: String,
    from: String,
    from_name: String,
    username: Option<String>,
    password: Option<String>,
}

impl SmtpConfig {
    pub fn from_env(env: &Env) -> Result<Option<Self>, AppError> {
        let Some(host) = env_str(env, "SMTP_HOST") else {
            return Ok(None);
        };

        let security = match env_str(env, "SMTP_SECURITY")
            .unwrap_or_else(|| "starttls".to_string())
            .to_lowercase()
            .as_str()
        {
            "off" => SmtpSecurity::Off,
            "starttls" => SmtpSecurity::StartTls,
            "force_tls" => SmtpSecurity::ForceTls,
            _ => {
                return Err(AppError::BadRequest(
                    "Invalid SMTP_SECURITY (expected: off/starttls/force_tls)".to_string(),
                ))
            }
        };

        let port = match env_str(env, "SMTP_PORT") {
            Some(raw) => raw.parse::<u16>().map_err(|_| {
                AppError::BadRequest("Invalid SMTP_PORT (expected integer 1-65535)".to_string())
            })?,
            None => match security {
                SmtpSecurity::ForceTls => 465,
                SmtpSecurity::StartTls => 587,
                SmtpSecurity::Off => 25,
            },
        };

        let from = env_str(env, "SMTP_FROM").ok_or_else(|| {
            AppError::BadRequest("SMTP_FROM is required when SMTP_HOST is set".to_string())
        })?;

        let username = env_str(env, "SMTP_USERNAME");
        let password = env_str(env, "SMTP_PASSWORD");
        if username.is_some() != password.is_some() {
            return Err(AppError::BadRequest(
                "SMTP_USERNAME and SMTP_PASSWORD must be set together".to_string(),
            ));
        }

        let helo_name =
            env_str(env, "SMTP_HELO_NAME").unwrap_or_else(|| "warden-worker".to_string());
        let from_name =
            env_str(env, "SMTP_FROM_NAME").unwrap_or_else(|| "Warden Worker".to_string());

        Ok(Some(Self {
            host,
            port,
            security,
            helo_name,
            from,
            from_name,
            username,
            password,
        }))
    }

    pub async fn send_register_verify_email(
        &self,
        to: &str,
        token: &str,
        origin: &str,
    ) -> Result<(), AppError> {
        let verify_url = format!(
            "{origin}/#/finish-signup/?email={}&token={}",
            encode_uri_component(to),
            encode_uri_component(token)
        );

        let subject = "Verify your email";
        let body = format!(
            "Verify this email address to continue signup.\r\n\r\nVerify link: {verify_url}\r\n\r\nIf you didn't request this, you can ignore this email."
        );

        self.send_email(to, subject, &body).await
    }

    pub async fn send_change_email_confirmation(
        &self,
        new_email: &str,
        old_email: &str,
        origin: &str,
    ) -> Result<(), AppError> {
        let subject = "Email change confirmation";
        let body = format!(
            "Your account email was changed.\r\n\r\nOld email: {old_email}\r\nNew email: {new_email}\r\n\r\nIf this was not you, review your account immediately: {origin}/#/settings/account"
        );
        self.send_email(new_email, subject, &body).await
    }

    pub async fn send_change_email_alert(
        &self,
        old_email: &str,
        new_email: &str,
        origin: &str,
    ) -> Result<(), AppError> {
        let subject = "Security alert: your account email changed";
        let body = format!(
            "Your account email has been changed from this address to: {new_email}\r\n\r\nIf this was not you, secure your account immediately: {origin}/#/settings/account"
        );
        self.send_email(old_email, subject, &body).await
    }

    pub async fn send_new_device_login_alert(
        &self,
        to: &str,
        device_identifier: &str,
        device_name: Option<&str>,
        device_type: i32,
        ip: &str,
        origin: &str,
    ) -> Result<(), AppError> {
        let subject = "New device login detected";
        let body = format!(
            "A new device logged into your account.\r\n\r\nDevice identifier: {device_identifier}\r\nDevice name: {}\r\nDevice type: {} ({device_type})\r\nIP: {ip}\r\nTime (UTC): {}\r\n\r\nIf this was not you, secure your account now: {origin}/#/settings/security",
            device_name.unwrap_or("Unknown"),
            device_type_to_string(device_type),
            Utc::now().to_rfc3339()
        );
        self.send_email(to, subject, &body).await
    }

    pub async fn send_auth_request_fallback_alert(
        &self,
        to: &str,
        auth_request_id: &str,
        request_device_identifier: &str,
        device_type: i32,
        ip: &str,
        origin: &str,
    ) -> Result<(), AppError> {
        let subject = "Device approval required";
        let body = format!(
            "A device approval request is waiting for your action.\r\n\r\nRequest ID: {auth_request_id}\r\nDevice identifier: {request_device_identifier}\r\nDevice type: {} ({device_type})\r\nIP: {ip}\r\nTime (UTC): {}\r\n\r\nOpen your vault to review this request: {origin}/#/vault",
            device_type_to_string(device_type),
            Utc::now().to_rfc3339()
        );
        self.send_email(to, subject, &body).await
    }

    pub async fn send_twofactor_email_token(&self, to: &str, token: &str) -> Result<(), AppError> {
        let subject = "Your verification code";
        let body = format!(
            "Your email verification code is: {token}\r\n\r\nIf you did not request this code, you can ignore this email."
        );
        self.send_email(to, subject, &body).await
    }

    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
        let secure_transport = match self.security {
            SmtpSecurity::Off => SecureTransport::Off,
            SmtpSecurity::StartTls => SecureTransport::StartTls,
            SmtpSecurity::ForceTls => SecureTransport::On,
        };

        let socket = Socket::builder()
            .secure_transport(secure_transport)
            .connect(self.host.as_str(), self.port)?;
        let mut stream = BufReader::new(socket);

        expect_code(&mut stream, &[220], "greeting").await?;
        ehlo_or_helo(&mut stream, &self.helo_name).await?;

        if self.security == SmtpSecurity::StartTls {
            send_line(&mut stream, "STARTTLS").await?;
            expect_code(&mut stream, &[220], "STARTTLS").await?;

            let secure_socket = stream.into_inner().start_tls();
            stream = BufReader::new(secure_socket);
            ehlo_or_helo(&mut stream, &self.helo_name).await?;
        }

        if let (Some(username), Some(password)) = (&self.username, &self.password) {
            smtp_auth(&mut stream, username, password).await?;
        }

        send_line(
            &mut stream,
            &format!("MAIL FROM:<{}>", sanitize_addr(&self.from)?),
        )
        .await?;
        expect_code(&mut stream, &[250], "MAIL FROM").await?;

        send_line(&mut stream, &format!("RCPT TO:<{}>", sanitize_addr(to)?)).await?;
        expect_code(&mut stream, &[250, 251], "RCPT TO").await?;

        send_line(&mut stream, "DATA").await?;
        expect_code(&mut stream, &[354], "DATA").await?;

        let mail_data = build_mail_data(self, to, subject, body)?;
        stream
            .get_mut()
            .write_all(mail_data.as_bytes())
            .await
            .map_err(io_err("write DATA body"))?;
        stream
            .get_mut()
            .write_all(b"\r\n.\r\n")
            .await
            .map_err(io_err("finalize DATA"))?;
        stream
            .get_mut()
            .flush()
            .await
            .map_err(io_err("flush DATA"))?;
        expect_code(&mut stream, &[250], "DATA commit").await?;

        send_line(&mut stream, "QUIT").await?;
        let _ = read_response(&mut stream).await;
        Ok(())
    }
}

fn env_str(env: &Env, key: &str) -> Option<String> {
    env.var(key).ok().map(|v| v.to_string()).and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn encode_uri_component(input: &str) -> String {
    js_sys::encode_uri_component(input)
        .as_string()
        .unwrap_or_else(|| input.to_string())
}

async fn ehlo_or_helo(stream: &mut BufReader<Socket>, helo_name: &str) -> Result<(), AppError> {
    send_line(stream, &format!("EHLO {helo_name}")).await?;
    let ehlo = read_response(stream).await?;
    if ehlo.code == 250 {
        return Ok(());
    }

    send_line(stream, &format!("HELO {helo_name}")).await?;
    expect_code(stream, &[250], "HELO").await
}

async fn smtp_auth(
    stream: &mut BufReader<Socket>,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
    let plain = general_purpose::STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
    send_line(stream, &format!("AUTH PLAIN {plain}")).await?;
    let resp = read_response(stream).await?;

    if resp.code == 235 || resp.code == 503 {
        return Ok(());
    }

    if resp.code == 334 {
        send_line(stream, &plain).await?;
        expect_code(stream, &[235, 503], "AUTH PLAIN challenge").await?;
        return Ok(());
    }

    send_line(stream, "AUTH LOGIN").await?;
    expect_code(stream, &[334], "AUTH LOGIN username challenge").await?;
    send_line(
        stream,
        &general_purpose::STANDARD.encode(username.as_bytes()),
    )
    .await?;
    expect_code(stream, &[334], "AUTH LOGIN password challenge").await?;
    send_line(
        stream,
        &general_purpose::STANDARD.encode(password.as_bytes()),
    )
    .await?;
    expect_code(stream, &[235, 503], "AUTH LOGIN").await
}

async fn send_line(stream: &mut BufReader<Socket>, line: &str) -> Result<(), AppError> {
    stream
        .get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(io_err("write SMTP command"))?;
    stream
        .get_mut()
        .flush()
        .await
        .map_err(io_err("flush SMTP command"))
}

async fn expect_code(
    stream: &mut BufReader<Socket>,
    expected_codes: &[u16],
    stage: &str,
) -> Result<(), AppError> {
    let response = read_response(stream).await?;
    if expected_codes.contains(&response.code) {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        "SMTP error at {stage}: {} {}",
        response.code, response.text
    )))
}

struct SmtpResponse {
    code: u16,
    text: String,
}

async fn read_response(stream: &mut BufReader<Socket>) -> Result<SmtpResponse, AppError> {
    let mut lines = Vec::new();
    let mut code: Option<u16> = None;

    loop {
        let mut line = String::new();
        let read = stream
            .read_line(&mut line)
            .await
            .map_err(io_err("read SMTP response"))?;
        if read == 0 {
            return Err(AppError::BadRequest(
                "SMTP connection closed unexpectedly".to_string(),
            ));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 {
            return Err(AppError::BadRequest(format!(
                "Malformed SMTP response: {trimmed}"
            )));
        }

        let parsed_code = trimmed[..3]
            .parse::<u16>()
            .map_err(|_| AppError::BadRequest(format!("Malformed SMTP code: {trimmed}")))?;
        if code.is_none() {
            code = Some(parsed_code);
        }

        lines.push(trimmed.to_string());

        let continuation = trimmed.as_bytes().get(3).copied() == Some(b'-');
        if !continuation {
            break;
        }
    }

    let code = code.unwrap_or(0);
    Ok(SmtpResponse {
        code,
        text: lines.join(" | "),
    })
}

fn build_mail_data(
    config: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, AppError> {
    let from_addr = sanitize_addr(&config.from)?;
    let to_addr = sanitize_addr(to)?;
    let from_name = sanitize_header(&config.from_name)?;
    let subject = sanitize_header(subject)?;
    let date = Utc::now().to_rfc2822();
    let msg_domain = from_addr
        .split('@')
        .nth(1)
        .unwrap_or(config.host.as_str())
        .to_string();
    let message_id = format!("<{}@{}>", Uuid::new_v4(), msg_domain);

    let mut out = String::new();
    out.push_str(&format!(
        "From: \"{from_name}\" <{from_addr}>\r\nTo: <{to_addr}>\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {message_id}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    ));

    let normalized_body = body.replace("\r\n", "\n").replace('\r', "\n");
    for line in normalized_body.split('\n') {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }

    Ok(out)
}

fn sanitize_header(input: &str) -> Result<String, AppError> {
    if input.contains('\r') || input.contains('\n') {
        return Err(AppError::BadRequest(
            "Invalid SMTP header value".to_string(),
        ));
    }
    Ok(input.trim().to_string())
}

fn sanitize_addr(input: &str) -> Result<String, AppError> {
    let trimmed = input.trim();
    if trimmed.contains('\r') || trimmed.contains('\n') || !trimmed.contains('@') {
        return Err(AppError::BadRequest(
            "Invalid SMTP email address".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn io_err(context: &'static str) -> impl Fn(std::io::Error) -> AppError {
    move |err| {
        log::warn!("smtp {context} failed: {err}");
        AppError::BadRequest(format!("SMTP I/O error at {context}: {err}"))
    }
}

fn device_type_to_string(device_type: i32) -> &'static str {
    match device_type {
        0 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        15 => "Android",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        _ => "Unknown",
    }
}
