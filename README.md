# Warden Worker

# 有问题？尝试 [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Lparksi/warden-worker)

Warden Worker 是一个运行在 Cloudflare Workers 上的 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）存储，核心代码为 Rust + WebAssembly，目标是“个人/家庭可用、低成本、免运维”。

项目遵循零知识模型：客户端本地完成加密，服务端仅保存密文。

## 最近更新

- `2026-02-13`：首个账号注册完成后，后续注册默认关闭（`feat(accounts)`）。
- `2026-02-13`：新增设备管理与设备审批流（`/api/auth-requests*`），支持已登录设备审批新设备登录（`feat(device manager)`）。
- `2026-02-13`：新增/完善 WebAuthn（通行密钥）注册、断言、无主密码登录、PRF 密钥材料上送与存储（`feat(webauthn)` + `fix(security)`）。
- `2026-02-11`：新增 Send（文本/文件）能力，文件支持分片存储（`send_file_chunks`）与下载。
- `2026-02-11`：新增 D1 占用统计接口 `GET /api/d1/usage`。

## 功能概览

- 无服务器部署：Cloudflare Workers + D1。
- Bitwarden 客户端兼容：浏览器扩展、桌面端、安卓端，以及多数第三方客户端。
- 核心能力：登录/同步、Cipher 增删改、文件夹、TOTP 二步验证、WebAuthn（含 PRF）。
- 设备能力：`knowndevice`、设备列表与推送 token 管理、设备审批授权流。
- 邮件能力：支持 SMTP 发送注册验证邮件、邮箱变更通知、新设备登录提醒，以及设备审批通知失败时的邮件兜底。
- Send 能力：文本 Send、文件 Send、文件上传与下载。
- 实时通知：`/notifications/hub` 与 `/notifications/anonymous-hub`（设备审批依赖）。

## 快速部署（Cloudflare）

### 0. 前置条件

- Cloudflare 账号
- Node.js + Wrangler：`npm i -g wrangler`
- Rust 稳定版工具链
- `worker-build`：`cargo install worker-build`

### 1. 创建 D1 数据库

```bash
wrangler d1 create vault1
```

将返回的 `database_id` 写入 `wrangler.jsonc` 的 `d1_databases`。

### 2. 全新初始化数据库

`sql/schema_full.sql` 会 `DROP TABLE`，仅适用于全新部署。

```bash
wrangler d1 execute vault1 --remote --file=sql/schema_full.sql
```

### 3. 已有实例升级（保留数据）

按文件名顺序执行 `sql/migrations/*.sql`。

```powershell
Get-ChildItem sql/migrations/*.sql | Sort-Object Name | ForEach-Object {
  wrangler d1 execute vault1 --remote --file=$_.FullName
}
```

### 4. 配置 Secrets

```bash
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put TWO_FACTOR_ENC_KEY
wrangler secret put SMTP_HOST
wrangler secret put SMTP_FROM
wrangler secret put SMTP_USERNAME
wrangler secret put SMTP_PASSWORD
```

- `JWT_SECRET`：访问令牌签名密钥
- `JWT_REFRESH_SECRET`：刷新令牌签名密钥
- `ALLOWED_EMAILS`：首号注册白名单（逗号分隔）。仅在数据库尚无用户时生效。
- `TWO_FACTOR_ENC_KEY`：可选，Base64 的 32 字节密钥，用于加密存储 TOTP 秘钥。
- SMTP（可选，用于 `/identity/accounts/register/send-verification-email` 发送验证邮件）：
  - `SMTP_HOST`：SMTP 主机（配置该项即启用 SMTP）
  - `SMTP_PORT`：可选，默认 `587`（`SMTP_SECURITY=starttls`）、`465`（`force_tls`）、`25`（`off`）
  - `SMTP_SECURITY`：可选，`starttls` / `force_tls` / `off`，默认 `starttls`
  - `SMTP_FROM`：发件邮箱（必填）
  - `SMTP_FROM_NAME`：可选，发件人名称，默认 `Warden Worker`
  - `SMTP_HELO_NAME`：可选，EHLO/HELO 名称，默认 `warden-worker`
  - `SMTP_USERNAME` + `SMTP_PASSWORD`：可选，需成对配置
  - 邮箱 2FA 相关可选参数：
    - `EMAIL_TOKEN_SIZE`：验证码位数，默认 `6`
    - `EMAIL_EXPIRATION_TIME`：验证码有效期（秒），默认 `600`
    - `EMAIL_ATTEMPTS_LIMIT`：验证码错误次数上限，默认 `3`

### 5. 配置并同步 Web Vault 前端

项目默认不再手动维护固定前端文件，而是按 `web-vault.config.json` 自动下载并解压
`dani-garcia/bw_web_builds` 指定 tag 的 release `.tar.gz`（默认 `v2026.1.1`）。
`static/web-vault` 已加入 `.gitignore`，不再入库，统一由同步脚本生成。
默认会移除 `*.map` sourcemap（避免 Cloudflare Workers 单文件 25 MiB 限制）。

```bash
node ./scripts/sync-web-vault.mjs
```

可选覆盖（临时切版本，不改配置文件）：

```bash
BW_WEB_BUILDS_TAG=v2026.1.1 node ./scripts/sync-web-vault.mjs
```

```powershell
$env:BW_WEB_BUILDS_TAG='v2026.1.1'
node .\scripts\sync-web-vault.mjs
```

可选覆盖 release 仓库与资产匹配（一般无需修改）：

```bash
BW_WEB_BUILDS_RELEASE_REPO=dani-garcia/bw_web_builds \
BW_WEB_BUILDS_ASSET_PATTERN='bw_web_v*.tar.gz' \
node ./scripts/sync-web-vault.mjs
```

如需保留 sourcemap（不推荐用于 Workers assets）：

```bash
BW_WEB_BUILDS_KEEP_SOURCEMAPS=true node ./scripts/sync-web-vault.mjs
```

### 6. 部署

```bash
wrangler deploy
```

部署后，将 Workers URL 或自定义域名填入 Bitwarden 客户端的“自托管服务器 URL”。

## 与 Bitwarden 客户端兼容的关键要求

- `GET /api/config` 返回的 `environment.notifications` 必须对应可用的 WebSocket 端点：
  `/notifications/hub` 与 `/notifications/anonymous-hub`。
- 通知端点需兼容最小 SignalR messagepack 握手：
  客户端发 `{"protocol":"messagepack","version":1}\x1e`，服务端回 `{}\x1e`。
- 匿名审批连接的查询参数需大小写不敏感（兼容 `token` 与 `Token`）。
- `wrangler.jsonc` 里 Durable Object 配置需保留：
  `durable_objects.bindings.NOTIFICATIONS_HUB`、对应 `migrations`，以及 `assets.run_worker_first` 中的 `/notifications/*`。

## 已实现的关键接口（节选）

- 配置与探测：`GET /api/config`、`GET /api/alive`、`GET /api/now`、`GET /api/version`
- 登录与认证：`POST /identity/accounts/prelogin`、`POST /identity/connect/token`
- 设备与审批：`GET /api/devices/knowndevice`、`GET /api/devices`、`POST /api/auth-requests`、`PUT /api/auth-requests/{id}`
- 邮箱二步验证：`POST /api/two-factor/get-email`、`POST /api/two-factor/send-email`、`PUT /api/two-factor/email`、`POST /api/two-factor/send-email-login`
- WebAuthn：`POST /api/webauthn/attestation-options`、`POST /api/webauthn/assertion-options`、`POST /api/webauthn`、`PUT /api/webauthn`
- Send：`GET/POST /api/sends`、`POST /api/sends/file/v2`、`POST /api/sends/{send_id}/file/{file_id}`、`GET /api/sends/{send_id}/{file_id}`
- 密码库：`GET /api/sync`、`POST /api/ciphers/create`、`PUT /api/ciphers/{id}`、`PUT /api/ciphers/{id}/delete`
- D1 占用统计：`GET /api/d1/usage`

## 客户端使用建议

- 安卓端若曾连接过其他自托管实例，建议移除账号后重新添加服务器，避免旧 remember token 干扰。
- 设备审批依赖通知通道；若通知未连通，可能出现“审批后页面不自动跳转/需手动刷新”。

## 开发注意事项

- D1 参数绑定禁止传 `undefined`。可选字段在 `.bind(&[...])` 时必须显式转 `null`（如 `JsValue::NULL` 或统一 `to_js_val(Option<T>)`）。
- 多端协议兼容尽量按 Vaultwarden/Bitwarden 行为对齐，尤其是认证、设备审批、通知与 WebAuthn 相关接口。
- `wrangler.jsonc` 的 build 阶段会自动执行 `node ./scripts/sync-web-vault.mjs`，按配置同步前端版本。

## 本地开发

```bash
wrangler d1 execute vault1 --local --file=sql/schema_full.sql
wrangler dev
```

本地可用 `.dev.vars` 注入 secrets。

## 许可证

MIT
