<h1 align="center">QBotMessager</h1>

<p align="center">
  <a href="https://www.rust-lang.org/"><img alt="Rust" src="https://img.shields.io/badge/Rust-1.100-000000?logo=rust&logoColor=white"></a>
  <a href="https://actix.rs/"><img alt="Actix Web" src="https://img.shields.io/badge/Actix_Web-4-2E7D32"></a>
  <a href="https://bun.sh/"><img alt="Bun" src="https://img.shields.io/badge/Bun-1.4-000000?logo=bun&logoColor=white"></a>
  <a href="https://nextjs.org/"><img alt="Next.js" src="https://img.shields.io/badge/Next.js-16-000000?logo=nextdotjs&logoColor=white"></a>
  <a href="https://www.mysql.com/"><img alt="MySQL" src="https://img.shields.io/badge/MySQL-8.4-4479A1?logo=mysql&logoColor=white"></a>
  <a href="https://docs.docker.com/compose/"><img alt="Docker Compose" src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white"></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img alt="License: AGPL v3" src="https://img.shields.io/badge/License-AGPL_v3-blue"></a>
</p>

<p align="center">面向钉钉、企业微信、飞书与 GitHub 的统一消息接入层：基于 Actix Web 的全 Rust 原生异步架构，单二进制托管静态控制台与 API，Tokio 全异步链路即时完成转换与推送，Access Token 常驻缓存、失效即刷；账号级频控与退避重试保障高峰稳定吞吐，多用户控制台按归属隔离资源，敏感凭据 Fernet 加密入库。</p>

## 目录

<p align="center">
  <a href="#功能特性">功能特性</a> ·
  <a href="#技术栈">技术栈</a> ·
  <a href="#系统架构">系统架构</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#配置说明">配置说明</a> ·
  <a href="#使用指南">使用指南</a> ·
  <a href="#接口一览">接口一览</a> ·
  <a href="#本地开发">本地开发</a> ·
  <a href="#目录结构">目录结构</a> ·
  <a href="#安全建议">安全建议</a> ·
  <a href="#已知限制">已知限制</a> ·
  <a href="#社区支持">社区支持</a> ·
  <a href="#许可证">许可证</a>
</p>

## 功能特性

- **多钩子类型入站**：`POST /webhook/dingtalk`、`/webhook/wecom`、`/webhook/feishu` 直接接受三个钩子类型的原始消息参数；GitHub 使用 `POST /webhook/github/{token}`，并校验 `X-Hub-Signature-256` 签名。
- **消息转换**：
  - 钉钉：text / markdown / link / actionCard / feedCard
  - 企业微信：text / markdown / markdown_v2 / news / image / file / voice / template_card
  - 飞书：text / post / image / share_chat / interactive
  - GitHub：全部事件类型；ping / push / pull_request / issues / release / workflow_run / workflow_job 使用专门格式，其余事件使用通用格式
- **QQ 推送**：支持 `msg_type=0` 纯文本与 `msg_type=2` Markdown，支持用户与群目标、账号级频控、401 自动刷新、5xx 与超频退避重试。
- **推送队列**：队列与业务库内嵌在同一 MySQL（apalis），Webhook 入队即确认，进程内 worker 按频控节奏发送，推送方不会因等待 QQ 响应而超时重投；重复投递按钩子类型投递 ID 去重。
- **轻量单进程**：全 Rust 原生实现，单二进制同时提供 API、Webhook 与 Next.js 静态导出产物；无需 Node、Redis 或 supervisord，Alpine 运行时内存占用低，启动即就绪。
- **多用户隔离**：每个用户独立管理自己的机器人、通道与推送日志，数据按 `owner_user_id` 隔离。
- **明暗主题**：默认跟随系统，控制台侧边栏与登录页可手动切换，并记住选择。
- **超级管理员**：可见并管理全部用户的资源；用户账号、邀请码、注册开关与 OAuth2 提供方仅超管可操作。
- **多种登录方式**：用户名或邮箱密码、OAuth2 授权码、通行密钥（WebAuthn），服务端会话 Cookie。
- **邮箱验证码**：配置 SMTP 后，注册、找回密码与 OAuth 账号首次设置密码需邮箱验证码；验证码邮件与站点风格一致。
- **推送审计**：记录钩子类型、推送来源、来源类型、目标、状态、错误码、耗时与请求 ID，支持分页与筛选。
- **敏感数据加密**：QQ AppSecret、OAuth Client Secret 以 Fernet 密文入库。

## 技术栈

| 层次 | 选型 |
|---|---|
| 后端 | Rust 1.100、Actix Web 4、sqlx 0.9（MySQL、编译期校验 SQL 与内嵌迁移）、reqwest + rustls（ring，无 OpenSSL） |
| 数据库 | MySQL 8.4；队列表与业务表同库 |
| 队列 | apalis + apalis-mysql；进程内 worker，无额外中间件 |
| 前端 | Next.js 16（App Router、静态导出）、React 19、Tailwind CSS v4、shadcn/ui；Bun 构建 |
| 部署 | 多阶段构建：Bun 构建前端 → Rust musl 静态二进制 → Alpine 运行时单进程 |
| 测试 | `cargo test`（单元 + 四组 MySQL 集成测试，含真实 ES256 签名的 Passkey 全路径）、`bun run typecheck` / `bun run build` |

## 系统架构

单个容器内只有一个进程：静态链接的 Rust 二进制监听 3000 端口，同服托管静态控制台与 API。Actix Web 的类型安全提取器在编译期约束请求负载，worker 线程按 CPU 核数自适应（默认最多 2，控制常驻内存），优雅退出时先把队列任务跑完。

```text
浏览器 / 推送方
      │
      ▼
Rust (Actix Web) :3000
  ├─ /            静态产物（Next.js 静态导出，SPA 回退）
  ├─ /api/*       认证与管理接口
  ├─ /webhook/*   钩子类型入站
  └─ 进程内 worker ──▶ QQ 机器人
      │
      ▼
MySQL 8.4（业务表 + apalis 队列表）
```

- 启动时执行 `sqlx::migrate!` 内嵌迁移（幂等），无需额外迁移容器或命令。
- Webhook 只做校验与入队，worker 按机器人频控节奏发送并写入推送日志；幂等守卫同样落在 MySQL 表，全链路无外部中间件。
- 启动时执行幂等引导：超管已存在则跳过；提供 `QQ_APPID` / `QQ_APP_SECRET` 时导入默认机器人，不覆盖已有配置。接入通道需在控制台创建（令牌只在创建时展示一次）。

## 快速开始

### 前置条件

- Docker 与 Docker Compose v2（源码构建方式需要 Compose）
- MySQL 8.4：使用预构建镜像时需自行提供；源码构建方式由 compose 自带

### 1. 准备配置

```bash
cp .env.example .env
```

编辑 `.env`，至少设置以下项（两种部署方式通用）：

```dotenv
APP_SECRET_KEY=请填入 Fernet 密钥
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=请替换为至少8位的强密码
```

> 对外地址、会话、限速与 QQ 推送等非敏感配置持久化在数据库中，登录后在「系统设置」修改，保存即生效，重建容器无需再提供 env。

生成 `APP_SECRET_KEY`（32 字节随机数的 base64url 形式）：

```bash
openssl rand -base64 32 | tr '+/' '-_'
```

### 2. 启动

#### 方式一：使用预构建镜像（推荐）

镜像发布在 GitHub Container Registry：`latest` 对应 `main` 分支最新构建，`vX.Y.Z` 对应版本标签，`sha-<短哈希>` 对应具体提交。

```bash
docker pull ghcr.io/caisre/qbotmessager:latest
```

预构建镜像不内置数据库，需在 `.env` 中显式指定连接串（sqlx 的协议前缀是 `mysql://`）：

```dotenv
MYSQL_URL=mysql://qbotmessager:<密码>@db:3306/qbotmessager
```

启动容器：

```bash
docker run -d --name qbotmessager --restart unless-stopped \
  --env-file .env -p 3000:3000 \
  --stop-timeout 30 \
  ghcr.io/caisre/qbotmessager:latest
```

> 镜像仅提供 `linux/amd64`；首次启动会自动完成迁移。MySQL 若也在 Docker 中，请让两个容器加入同一网络，并用服务名作为连接主机。

#### 方式二：源码构建（compose 自带 MySQL）

在 `.env` 中补充 MySQL 密码：

```dotenv
MYSQL_PASSWORD=请替换为强密码
MYSQL_ROOT_PASSWORD=请替换为强密码
```

构建并启动：

```bash
docker compose up -d --build
```

> 构建阶段依次使用 `oven/bun` 与 `rust:alpine` 镜像；国内网络可先把基础镜像同步到本地仓库，再通过 `ALPINE_VERSION` / `BUN_VERSION` / `RUST_VERSION` 构建参数锁定版本。

### 3. 首次登录

访问 `http://localhost:3000`，使用 `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` 登录。首次启动会：

1. 创建超级管理员账号；
2. 若配置了 `QQ_APPID` / `QQ_APP_SECRET`，导入默认机器人、默认推送目标与钉钉 / 企业微信 / 飞书三条通道（GitHub 通道需在「机器人」页手动创建）；
3. 默认关闭注册入口，需要时在「安全设置」中开启，并在「用户管理」中生成邀请码。
4. 如需邮箱验证码（注册验证、找回密码），先在「系统设置 → 邮件服务」填写 SMTP 服务器与发件人；未配置时注册仍只校验邀请码。

## 配置说明

### 环境变量（敏感与启动依赖）

| 变量 | 说明 | 默认 |
|---|---|---|
| `MYSQL_URL` | 数据库连接串（`mysql://`）；源码 compose 自动注入为 `db` 服务的 `qbotmessager` 库，预构建镜像需在 `.env` 中显式设置 | 空 |
| `MYSQL_PASSWORD` / `MYSQL_ROOT_PASSWORD` | MySQL 业务账号与 root 密码（compose 必填） | 无 |
| `APP_SECRET_KEY` | Fernet 主密钥，用于加密库内敏感字段；缺失时默认拒绝启动 | 空（必须设置） |
| `ALLOW_PLAINTEXT_SECRETS` | 仅本地调试使用：设为 `true` 时允许缺少主密钥并以明文保存敏感字段 | `false` |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | 初始超级管理员；账号已存在时仅在密码匹配且系统无启用的超管时提升，不改密码 | 空 |
| `QQ_APPID` / `QQ_APP_SECRET` / `OPENID` | 首启导入的机器人凭据与默认推送目标 | 空 |
| `TRUST_PROXY` | 是否信任上游反向代理的 `X-Forwarded-For`；直连部署保持 `false`，由 Nginx/Caddy 转发时设 `true`（取最右侧一跳） | `false` |
| `PUSH_QUEUE_MAX` / `PUSH_QUEUE_MAX_PER_USER` | 推送队列总积压上限 / 单用户积压上限；单用户超额时仅该用户的新投递返回忙 | `200` / `20` |
| `RETENTION_*_DAYS` | 过期会话 / 验证码 / 发码守卫 / 审计日志 / 推送日志 / 日志预览的保留天数；`0` 关闭对应清理 | `30` / `7` / `7` / `180` / `90` / `7` |
| `RETENTION_INTERVAL_HOURS` | 数据保留清理任务执行间隔（小时） | `24` |
| `STATIC_DIR` | 前端静态产物目录；容器内为 `/app/web`，本地直跑可指向 `../web/out` | `./web/out` |
| `WORKERS` | Actix worker 线程数；留空按 CPU 核数但最多 2，降低容器常驻内存 | 最多 2 |
| `PORT` / `APP_PORT` | 容器内监听端口 / 宿主机映射端口 | `3000` / `3000` |
| `ALPINE_VERSION` / `BUN_VERSION` / `RUST_VERSION` | 构建阶段基础镜像版本（compose 构建参数） | `3.24` / `1.4.5` / `1.100` |

### 系统设置（数据库内持久化）

以下配置在管理台「系统设置」页面修改，保存后立即生效。同名环境变量仅在首次启动、库内尚无该设置时作为初始值导入，之后以数据库为准。

| 设置项 | 说明 | 默认 |
|---|---|---|
| 对外访问地址（`PUBLIC_BASE_URL`） | 用于生成 Webhook URL 与 OAuth 回调 | 空（按请求头推导） |
| 统计时区（`TIMEZONE`） | 留空取容器 `TZ`，再退回本机时区 | 空 |
| 日志级别（`LOG_LEVEL`） | 通过 `RUST_LOG` 生效，保存后立即调整 | `INFO` |
| 请求体上限（`MAX_BODY_BYTES`） | Webhook 单次请求体上限（字节） | `65536` |
| GitHub 请求体上限（`GITHUB_MAX_BODY_BYTES`） | GitHub Webhook 单次请求体上限（字节）；GitHub 自身负载上限为 25MB | `2097152` |
| 允许 URL 传凭据（`WEBHOOK_ALLOW_QUERY_TOKEN`） | 是否允许 `?token=`（会落入访问日志） | `false` |
| 允许邀请注册（`REGISTER_ENABLED`） | 也可在「安全设置」中切换 | `false` |
| 会话有效期（`SESSION_TTL_HOURS`） | 对新登录生效 | `72` |
| Cookie 仅限 HTTPS（`COOKIE_SECURE`） | 对外地址为 https 时自动开启 | `false` |
| 通行密钥 RP ID / 名称（`RP_ID` / `RP_NAME`） | WebAuthn 依赖方标识与展示名 | 空 / 项目名 |
| 登录失败限速（`LOGIN_MAX_FAILURES` / `LOGIN_IP_MAX_FAILURES` / `LOGIN_WINDOW_SECONDS`） | 同一 (IP, 账号) / 同一 IP 的失败上限与统计窗口 | `5` / `30` / `900` |
| SMTP 服务器（`SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY`） | 验证码邮件服务器；连接方式可选 STARTTLS / SSL / 明文 | 空 / `587` / `starttls` |
| SMTP 账号（`SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM`） | 登录凭据与发件人；密码以 Fernet 密文入库，留空保持不变 | 空 |
| 验证码策略（`EMAIL_CODE_TTL_MINUTES` / `EMAIL_CODE_RESEND_SECONDS` / `EMAIL_CODE_HOURLY_LIMIT`） | 有效期、重发间隔与同一邮箱每小时上限 | `10` / `60` / `5` |
| 单来源发码上限（`EMAIL_CODE_IP_HOURLY_LIMIT`） | 同一来源地址每小时最多发起的验证码请求数，防止对大量邮箱触发邮件发送 | `30` |
| QQ API 域名（`QQ_HOST`） | 机器人未单独配置时使用的默认地址 | `https://api.bot.qq.com` |
| QQ 频控（`QQ_QPS` / `QQ_QPM` / `QQ_MIN_INTERVAL`） | 账号级频控，保存后重建限速器 | `5` / `30` / `0.21` |
| 内容长度上限（`MARKDOWN_MAX_LEN` / `TEXT_MAX_LEN`） | 下发内容长度上限 | `4000` / `2000` |

## 使用指南

### 创建机器人与通道

1. 在「机器人」页新增机器人，填写 AppID、AppSecret 与默认接收方（openid 或群 openid）。同一账号下 AppID 不可重复，QQ 频控与 token 按 AppID 共享。
2. 在同一页新增通道，选择钩子类型并填写推送来源（可选，用于区分 Webhook 的使用位置）后即生成 Webhook Token 与完整 Webhook 地址，**只展示这一次**，请立即复制保存。GitHub 的 Webhook 设置中没有单独的 token 字段：token 已包含在 `/webhook/github/{token}` 地址中，填入 Payload URL 即可；创建时还会生成 Secret，需填到 GitHub 的 Secret 字段。
3. 通道可在「轮换」后立即失效旧 token，也可停用而不删除；GitHub 通道轮换会同时更换签名密钥，需要同步更新 GitHub 配置。

### 发送 Webhook

按对应钩子类型的原始格式 POST。钉钉 / 企业微信 / 飞书的鉴权支持两种方式（优先级从高到低）：`X-Webhook-Token` 请求头、`Authorization: Bearer <token>` 请求头。查询参数 `?token=` 默认关闭（凭据会落进访问日志），需要时在「系统设置」中开启：

```bash
curl -X POST http://localhost:3000/webhook/dingtalk \
  -H "X-Webhook-Token: <通道 token>" \
  -H "Content-Type: application/json" \
  -d '{"msgtype":"text","text":{"content":"部署完成"}}'
```

- **推送目标**：请求体顶层可选 `openid` 或 `group_openid`，缺省使用机器人配置的默认目标。
- **响应格式**：钉钉 / 企业微信返回 `errcode` / `errmsg`，飞书返回 `code` / `msg` / `data`。
- **GitHub**：token 只在 URL 路径中传递，并强制校验 `X-Hub-Signature-256`；成功返回 `{"ok": true}`。所有事件类型都会处理，已知事件使用专门格式、其余使用通用格式；`workflow_run` 仅推送 completed，其余动作返回 200 以免 GitHub 判定投递失败并重试。
- **状态码**：鉴权或 GitHub 签名失败返回 401；目标缺失或消息不支持返回 400；QQ 侧失败返回 502，并写入推送日志。

### 用户与权限

| 角色 | 权限 |
|---|---|
| `super_admin` | 管理全部用户的机器人、通道与推送日志；管理用户、邀请码、注册开关、OAuth2 提供方与系统设置 |
| `user` | 仅管理本人创建的机器人、通道与推送日志 |

- 注册需邀请码，注册用户固定为 `user`；邀请码由超级管理员签发，可限定邮箱、次数与有效期。
- 用户名全局唯一（忽略大小写），可用于登录；未填写时按邮箱前缀自动生成，冲突时追加 `-2`、`-3` 等后缀。数据库对 `lower(name)` 建唯一索引兜底。
- 系统至少保留一个启用的超级管理员，且不能修改自己的角色或账号状态。
- OAuth2 提供方默认「邮箱不可信」：管理端开启「信任邮箱」且本次授权响应标记邮箱已验证时，才会用同邮箱自动关联已有本地账号。首次通过 OAuth 建号还必须携带有效邀请码，邀请码限定邮箱时须与提供方返回的邮箱一致；邀请码名额与建号同事务占用。

## 接口一览

| 分组 | 路径 | 说明 |
|---|---|---|
| 健康检查 | `GET /healthz`、`GET /readyz` | 存活与就绪探针（含数据库连通性） |
| 数据面 | `POST /webhook/{hook_type}` | `dingtalk` / `wecom` / `feishu` |
| | `POST /webhook/github/{token}` | GitHub Webhook，校验 `X-Hub-Signature-256` |
| 认证 | `GET /api/auth/providers` | 注册开关、可用登录方式与邮件验证码开关（公开） |
| | `POST /api/auth/login`、`/logout`、`/register` | 用户名或邮箱密码登录、退出、邀请码注册（配置 SMTP 后需邮箱验证码） |
| | `POST /api/auth/email-code`、`/password/reset` | 发送注册/找回密码验证码、用验证码重置密码 |
| | `GET /api/auth/me` | 当前用户信息 |
| | `GET /api/auth/oauth/{key}/start`、`/callback` | OAuth2 授权码流程；`start?invite_code=` 携带首次建号所需邀请码 |
| | `GET /api/auth/passkey`、`POST /api/auth/passkey/*` | 通行密钥注册与登录 |
| 管理台 | `/api/admin/bot-profiles`、`/channels` | 资源增删改查（按归属过滤） |
| | `GET /api/admin/logs`、`/stats` | 推送日志与统计 |
| 超管 | `/api/admin/users`、`/invites`、`/oauth-providers`、`/settings` | 用户、邀请码、OAuth2 与系统设置 |

> 管理接口均需登录会话；普通用户只能访问本人资源，超管专属接口对其他角色返回 403。

## 本地开发

后端（首次运行会在 `MYSQL_URL` 指向的库执行迁移）：

```bash
cd backend
export MYSQL_URL="mysql://qbotmessager:${MYSQL_PASSWORD}@localhost:3306/qbotmessager"
export STATIC_DIR=../web/out
cargo run
```

前端构建（产物供 Rust 同服托管）：

```bash
cd web
bun install
bun run build
```

前端热更新开发（仅调试界面）：

```bash
cd web
bun run dev
```

> 前端为静态导出，开发服务器不反代 `/api` 与 `/webhook`；接口联调请先 `bun run build`，再访问 Rust 服务的 3000 端口。

### 测试

```bash
cd backend
cargo test --all-features
```

集成测试需要四个 MySQL 库（auth / admin / webhook / bootstrap）。本地默认连接 `127.0.0.1:13306`；也可通过 `MYSQL_URL` 覆盖，单套件运行时设为对应库即可（如 `cargo test --test bootstrap_it`）。CI 使用 MySQL 8.4 service 容器并逐套件注入连接串；前端检查：

```bash
cd web
bun run typecheck
bun run build
```

## 目录结构

```text
.
├── .github/workflows/      CI：Rust/Bun 检查与镜像发布
├── backend/                Rust 后端（Actix Web）
│   ├── src/api/            路由：auth / admin / webhook / health
│   ├── src/auth/           会话、密码、OAuth2、WebAuthn
│   ├── src/adapters/       钉钉 / 企业微信 / 飞书 / GitHub 消息解析
│   ├── src/services/       QQ 客户端、邮件、频控、推送队列与执行
│   ├── src/worker.rs       apalis 推送 worker 与定时任务
│   ├── migrations/         sqlx 迁移（编译期内嵌，启动时执行）
│   └── tests/              认证 / 管理 / Webhook / 启动引导 / 数据保留集成测试
├── web/                    Next.js 控制台（静态导出）
│   ├── app/(console)/      概览 / 机器人 / 日志 / 系统设置 / 用户 / 安全
│   └── lib/                类型、请求封装、通行密钥
├── Dockerfile              Bun 构建 → Rust musl 静态二进制 → Alpine 运行时
└── docker-compose.yml
```

## 安全建议

- 生产环境务必设置 `APP_SECRET_KEY`（缺失时默认拒绝启动），密钥丢失将无法解密已入库的敏感字段。仅本地调试可显式设置 `ALLOW_PLAINTEXT_SECRETS=true` 降级明文。
- 使用 HTTPS，并在「系统设置」中开启 Cookie 仅限 HTTPS、填写真实对外地址，保证 OAuth 回调与 Webhook 地址正确。HTTPS 下会话 Cookie 自动使用 `__Host-` 前缀；响应下发带 `includeSubDomains` 的 HSTS，并按页面内联脚本哈希生成 CSP，不使用 `script-src 'unsafe-inline'`。
- 过期会话、验证码、审计与推送日志由 worker 定期清理；推送日志的内容预览默认 7 天后清空，可通过 `RETENTION_*` 环境变量调整或关闭。
- 部署在反向代理之后时设置 `TRUST_PROXY=true`，否则登录限速只能看到代理地址。
- 只有在提供方确实验证过邮箱归属时才开启 OAuth2 提供方的「信任邮箱」，否则同邮箱的本地账号可能被冒名登录接管。
- 不要将 MySQL 端口暴露到公网（compose 未映射 3306）。
- Webhook token 具有推送权限，泄露后请在「机器人 → 通道」中立即轮换。库内只保存 token 的 SHA-256 哈希，明文仅在创建/轮换时展示一次，无法再次查看。GitHub 通道的 URL token 与 Secret 相互独立：token 泄露不足以伪造投递，但仍应同时轮换并同步更新 GitHub 配置。
- 添加/删除通行密钥、绑定/解绑第三方账号前，需要会话在最近 10 分钟内完成过身份验证；未设置密码的账号请退出后重新登录，再执行这些操作。
- 邀请码按需签发并限定邮箱与有效期，注册入口用完即关。
- 登录失败限速按 (来源地址, 账号) 计数：部署在反向代理之后时设置 `TRUST_PROXY=true` 以取得真实客户端地址。
- 验证码发码按来源地址限速（默认每小时 30 次）：同一来源超出后返回 429。反代未透传真实客户端地址时所有用户共享同一额度，用户较多时应调高「单来源发码上限」并设置 `TRUST_PROXY=true`。

## 已知限制

- 附件（图片 / 文件 / 语音）不会下发到 QQ：需要先调用 QQ 富媒体上传接口，当前未实现。
- 飞书新版 schema 2.0 卡片的 `card.body.elements` 未解析（旧版 `card.elements` 正常）。
- 钉钉 `audio` / `file` / `picture` 类型未支持。
- 除 GitHub 外，入站使用自建 token（`X-Webhook-Token` 或 `Authorization: Bearer`），不校验钩子签名（钉钉 sign、飞书 sign / verification token）；适合由用户侧将钩子格式请求转发到本服务。
- GitHub 通道仅接受 `application/json` 投递，且不支持在「推送调试」页构造事件；调试请直接使用 GitHub 的 Webhook 测试投递。
- 真实 QQ 推送与 OAuth2 第三方登录需要有效凭据，自动化测试仅覆盖到打桩层。
- 前端静态导出后，`bun run dev` 仅用于界面调试，接口需由 Rust 服务提供。

## 社区支持

- [LINUX DO](https://linux.do)：交流使用经验、反馈问题与建议。

## 许可证

本项目基于 [GNU Affero General Public License v3.0](./LICENSE)（AGPL-3.0）开源，Copyright (c) 2026 CaiSre。

AGPL-3.0 是强 copyleft 许可证：修改并分发本项目，或将其作为网络服务对外提供时，需要以同一许可证公开对应源码。内部自用、不对外提供服务的部署不受额外约束。
