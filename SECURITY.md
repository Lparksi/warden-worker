# Security Policy

## Supported Versions

This project is currently in active development. Security updates will be provided for the latest version only.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Security Features

Warden Worker implements multiple layers of security:

### 1. Zero-Knowledge Architecture
- Client-side encryption: All encryption/decryption happens on the client
- Server stores only encrypted data (ciphertext)
- Master password never transmitted to server
- Server cannot decrypt user data

### 2. Authentication & Authorization
- JWT-based authentication with HMAC-SHA256 signing
- Separate access tokens (2 hours) and refresh tokens (30 days)
- Constant-time comparison for all security-sensitive operations
- Device-based authentication with approval workflow

### 3. Cryptographic Security
- PBKDF2-SHA256 for key derivation
- AES-256-GCM for authenticated encryption
- P-256 ECDSA for WebAuthn signatures
- Secure random number generation using OS RNG

### 4. Two-Factor Authentication
- TOTP (Time-based One-Time Password) support
- Email-based 2FA with rate limiting
- WebAuthn/FIDO2 support with PRF
- Attempt limiting and token expiration

### 5. Database Security
- Parameterized queries (no SQL injection)
- Foreign key constraints with CASCADE deletion
- Prepared statements for all database operations

### 6. Network Security
- HTTPS/TLS enforced (Cloudflare Workers)
- CORS configured appropriately
- Security headers enabled:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - Content-Security-Policy
  - Referrer-Policy
  - Permissions-Policy

## Security Configuration

### Required Secrets

The following secrets must be configured securely:

```bash
# Authentication Secrets (REQUIRED)
wrangler secret put JWT_SECRET              # Use strong random string (32+ bytes)
wrangler secret put JWT_REFRESH_SECRET      # Different from JWT_SECRET

# Two-Factor Encryption Key (OPTIONAL but RECOMMENDED)
wrangler secret put TWO_FACTOR_ENC_KEY      # Base64-encoded 32-byte key

# Registration Control (OPTIONAL)
wrangler secret put ALLOWED_EMAILS          # Comma-separated email whitelist

# SMTP Configuration (OPTIONAL)
wrangler secret put SMTP_HOST
wrangler secret put SMTP_FROM
wrangler secret put SMTP_USERNAME
wrangler secret put SMTP_PASSWORD
```

### Generating Secure Secrets

#### JWT Secrets
```bash
# Generate a secure random secret
openssl rand -base64 32
```

#### Two-Factor Encryption Key
```bash
# Generate a 32-byte key and encode as base64
openssl rand -base64 32
```

## Security Best Practices

### For Deployment

1. **Use Strong Secrets**
   - Generate cryptographically random secrets
   - Use different secrets for JWT_SECRET and JWT_REFRESH_SECRET
   - Never commit secrets to version control
   - Rotate secrets periodically

2. **Enable SMTP**
   - Configure SMTP for security notifications
   - Use STARTTLS or force TLS
   - Use application-specific passwords if available

3. **Configure Email Whitelist**
   - Set ALLOWED_EMAILS for first account registration
   - After first account created, registration is automatically disabled

4. **Use Custom Domain**
   - Configure a custom domain with proper DNS
   - Enable Cloudflare's security features

5. **Monitor Usage**
   - Regularly check `/api/d1/usage` for database usage
   - Monitor for unusual patterns

### For Users

1. **Use Strong Master Password**
   - Minimum 12 characters
   - Mix of letters, numbers, symbols
   - Unique to this vault

2. **Enable Two-Factor Authentication**
   - Use TOTP (authenticator app) or WebAuthn
   - Keep backup codes secure

3. **Use WebAuthn When Possible**
   - Hardware security keys (YubiKey, etc.)
   - Biometric authentication
   - Most secure 2FA option

4. **Secure Your Email Account**
   - Email is used for account recovery
   - Enable 2FA on your email provider
   - Use a strong, unique password

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it privately:

1. **Email**: Create a GitHub security advisory at https://github.com/Lparksi/warden-worker/security/advisories/new
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 30 days
  - Medium: Within 90 days
  - Low: Best effort

### Disclosure Policy

- We follow coordinated disclosure
- Security advisory published after fix is deployed
- Credit given to reporters (if desired)

## Security Updates

Security updates are announced through:
- GitHub Security Advisories
- Release notes with `[SECURITY]` tag
- README.md update log

## Security Audit

A comprehensive security audit was conducted on 2026-02-13. See [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) for details.

Key findings:
- ✅ No dependency vulnerabilities
- ✅ No SQL injection vulnerabilities
- ✅ Proper cryptographic implementations
- ✅ Secure authentication and authorization

## Additional Resources

- [Bitwarden Security Whitepaper](https://bitwarden.com/images/resources/security-white-paper-2021.pdf)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://www.sans.org/top25-software-errors/)

## Acknowledgments

We would like to thank the following individuals and organizations for their contributions to the security of this project:

- Bitwarden and Vaultwarden projects for security best practices
- Cloudflare Workers security team
- Security researchers who responsibly disclose vulnerabilities

---

**Last Updated**: 2026-02-13
