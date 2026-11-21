# QBotMessager

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8.4-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Tests](https://img.shields.io/badge/tests-44%20passed-brightgreen)](#测试)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue)](https://www.gnu.org/licenses/agpl-3.0)

> 接收钉钉、企业微信、飞书的 Webhook，统一转换为 QQ 机器人消息并推送；内置多用户控制台，按用户隔离机器人配置与推送日志。

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
- [接口一览](#接口一览)
- [本地开发](#本地开发)
- [目录结构](#目录结构)
- [安全建议](#安全建议)
- [已知限制](#已知限制)
- [许可证](#许可证)

## 功能特性

- **多平台入站**：`POST /webhook/dingtalk`、`/webhook/wecom`、`/webhook/feishu`，直接接受三个平台的原始消息参数。
- **消息转换**：
  - 钉钉：text / markdown / link / actionCard / feedCard
  - 企业微信：text / markdown / markdown_v2 / news / image / file / voice / template_card
  - 飞书：text / post / image / share_chat / interactive
- **QQ 推送**：支持 `msg_type=0` 纯文本与 `msg_type=2` Markdown，支持用户与群目标、账号级频控、401 自动刷新、5xx 与超频退避重试。
- **多用户隔离**：每个用户独立管理自己的机器人、通道、环境配置与推送日志，数据按 `owner_user_id` 隔离。
- **超级管理员**：可见并管理全部用户的资源；用户账号、邀请码、注册开关与 OAuth2 提供方仅超管可操作。
- **多种登录方式**：邮箱密码、OAuth2 授权码、通行密钥（WebAuthn），服务端会话 Cookie。
- **推送审计**：记录平台、来源类型、目标、状态、错误码、耗时与请求 ID，支持分页与筛选。
- **敏感数据加密**：QQ AppSecret、OAuth Client Secret、加密型环境配置以 Fernet 密文入库。

## 技术栈

| 层次 | 选型 |
|---|---|
| 后端 | FastAPI、SQLAlchemy 2（async）、Alembic、Pydantic v2 |
| 数据库 | MySQL 8.4（asyncmy）；测试使用 SQLite（aiosqlite） |
| 前端 | Next.js 16（App Router、standalone）、React 19、Tailwind CSS v4、shadcn/ui |
| 部署 | 单容器：supervisord 同时托管 Next.js 与 Uvicorn，启动时自动执行迁移 |
| 测试 | pytest、pytest-asyncio、FastAPI TestClient |

## 系统架构

单容器内运行两个进程，由 supervisord 托管：

```text
浏览器 / 推送方
      │
      ▼
Next.js :3000  ──/api/*、/webhook/* 反代──▶  FastAPI :8000
      │                                            │
      └──────────────── 同一容器 ──────────────────┘
                                                   ▼
                                             MySQL 8.4
```

- 容器入口 `deploy/entrypoint.sh` 等待数据库就绪后执行 `alembic upgrade head`，再启动 supervisord。
- 后端启动时执行幂等引导：创建超级管理员，并在提供 `QQ_APPID` / `QQ_APP_SECRET` 时导入默认机器人及三条通道。

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
BOOTSTRAP_ADMIN_PASSWORD=请替换为强密码
PUBLIC_BASE_URL=http://localhost:3000
```

生成 `APP_SECRET_KEY`：

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. 启动

#### 方式一：使用预构建镜像（推荐）

镜像发布在 GitHub Container Registry：`latest` 对应 `main` 分支最新构建，`vX.Y.Z` 对应版本标签，`sha-<短哈希>` 对应具体提交。

```bash
docker pull ghcr.io/caisre/qbotmessger:latest
```

预构建镜像不内置数据库，需在 `.env` 中显式指定连接串：

```dotenv
MYSQL_URL=mysql+asyncmy://qbotmessager:<密码>@<MySQL 主机>:3306/qbotmessager
```

启动容器：

```bash
docker run -d --name qbotmessager --restart unless-stopped \
  --env-file .env -p 3000:3000 \
  ghcr.io/caisre/qbotmessger:latest
```

> 镜像仅提供 `linux/amd64`；首次启动会等待数据库就绪并自动完成迁移。MySQL 若也在 Docker 中，请让两个容器加入同一网络，并用服务名作为连接主机。

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

> 国内网络可在 `.env` 中把 `PYPI_MIRROR`、`NPM_MIRROR` 改为镜像源后再构建。

### 3. 首次登录

访问 `http://localhost:3000`，使用 `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` 登录。首次启动会：

1. 创建超级管理员账号；
2. 若配置了 `QQ_APPID` / `QQ_APP_SECRET`，导入默认机器人、默认推送目标与钉钉 / 企业微信 / 飞书三条通道；
3. 默认关闭注册入口，需要时在「安全设置」中开启，并在「用户管理」中生成邀请码。

## 配置说明

| 变量 | 说明 | 默认 |
|---|---|---|
| `MYSQL_URL` | 数据库连接串；源码 compose 自动注入为 `db` 服务的 `qbotmessager` 库，预构建镜像需在 `.env` 中显式设置 | 空 |
| `MYSQL_PASSWORD` / `MYSQL_ROOT_PASSWORD` | MySQL 业务账号与 root 密码（compose 必填） | 无 |
| `APP_SECRET_KEY` | Fernet 主密钥，用于加密库内敏感字段 | 空（降级明文并告警） |
| `PUBLIC_BASE_URL` | 对外访问地址，用于生成 Webhook URL 与 OAuth 回调 | 空（按请求头推导） |
| `COOKIE_SECURE` | 会话 Cookie 是否仅限 HTTPS | `false` |
| `SESSION_TTL_HOURS` | 会话有效期（小时） | `72` |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | 初始超级管理员；账号已存在时不改动 | 空 |
| `REGISTER_ENABLED` | 是否允许凭邀请码注册（可被后台设置覆盖） | `false` |
| `QQ_APPID` / `QQ_APP_SECRET` / `OPENID` | 首启导入的机器人凭据与默认推送目标 | 空 |
| `QQ_HOST` | QQ 开放平台地址 | `https://api.bot.qq.com` |
| `QQ_QPS` / `QQ_QPM` / `QQ_MIN_INTERVAL` | 账号级频控 | `5` / `30` / `0.21` |
| `MARKDOWN_MAX_LEN` / `TEXT_MAX_LEN` | 下发内容长度上限 | `4000` / `2000` |
| `MAX_BODY_BYTES` | Webhook 请求体上限 | `65536` |
| `RP_ID` / `RP_NAME` | WebAuthn 依赖方标识与名称 | `localhost` / 项目名 |
| `LOG_LEVEL` | 日志级别 | `INFO` |
| `APP_PORT` | 宿主机映射端口（源码 compose） | `3000` |
| `PYPI_MIRROR` / `NPM_MIRROR` | 构建时使用的软件源 | 官方源 |

## 使用指南

### 创建机器人与通道

1. 在「机器人」页新增机器人，填写 AppID、AppSecret 与默认接收方（openid 或群 openid）。
2. 在同一页新增通道，选择平台后即生成 `webhook_token` 与完整 Webhook 地址，可直接复制。
3. 通道可在「轮换」后立即失效旧 token，也可停用而不删除。

### 发送 Webhook

按对应平台的原始格式 POST，鉴权使用 `X-Webhook-Token` 请求头（或 `?token=` 查询参数）：

```bash
curl -X POST http://localhost:3000/webhook/dingtalk \
  -H "X-Webhook-Token: <通道 token>" \
  -H "Content-Type: application/json" \
  -d '{"msgtype":"text","text":{"content":"部署完成"}}'
```

- **推送目标**：请求体顶层可选 `openid` 或 `group_openid`，缺省使用机器人配置的默认目标。
- **响应格式**：钉钉 / 企业微信返回 `errcode` / `errmsg`，飞书返回 `code` / `msg` / `data`。
- **状态码**：鉴权失败返回 401；目标缺失或消息不支持返回 400；QQ 侧失败返回 502，并写入推送日志。

### 用户与权限

| 角色 | 权限 |
|---|---|
| `super_admin` | 管理全部用户的机器人、通道、环境配置与推送日志；管理用户、邀请码、注册开关、OAuth2 提供方 |
| `user` | 仅管理本人创建的机器人、通道、环境配置与推送日志 |

- 注册需邀请码，注册用户固定为 `user`；邀请码由超级管理员签发，可限定邮箱、次数与有效期。
- 系统至少保留一个启用的超级管理员，且不能修改自己的角色或账号状态。

## 接口一览

| 分组 | 路径 | 说明 |
|---|---|---|
| 健康检查 | `GET /healthz`、`GET /readyz` | 存活与就绪探针（含数据库连通性） |
| 数据面 | `POST /webhook/{platform}` | `dingtalk` / `wecom` / `feishu` |
| 认证 | `GET /api/auth/providers` | 注册开关与可用登录方式（公开） |
| | `POST /api/auth/login`、`/logout`、`/register` | 邮箱密码登录、退出、邀请码注册 |
| | `GET /api/auth/me` | 当前用户信息 |
| | `GET /api/auth/oauth/{key}/start`、`/callback` | OAuth2 授权码流程 |
| | `GET /api/auth/passkey`、`POST /api/auth/passkey/*` | 通行密钥注册与登录 |
| 管理台 | `/api/admin/bot-profiles`、`/channels`、`/env-configs` | 资源增删改查（按归属过滤） |
| | `GET /api/admin/logs`、`/stats` | 推送日志与统计 |
| 超管 | `/api/admin/users`、`/invites`、`/oauth-providers`、`/settings` | 用户、邀请码、OAuth2 与系统设置 |

> 管理接口均需登录会话；普通用户只能访问本人资源，超管专属接口对其他角色返回 403。

## 本地开发

后端：

```bash
uv sync
uv run alembic upgrade head
uv run uvicorn server.main:app --reload --port 8000
```

前端：

```bash
cd web
npm ci
npm run dev
```

前端开发服务器会把 `/api/*`、`/webhook/*` 反代到 `BACKEND_ORIGIN`（默认 `http://127.0.0.1:8000`）。未使用 MySQL 时可通过 `MYSQL_URL=sqlite+aiosqlite:///./dev.db` 指向本地 SQLite。

### 测试

```bash
uv run pytest
```

测试使用临时 SQLite，覆盖适配器、渲染、频控、QQ 客户端、鉴权、用户隔离、Webhook 数据面与推送日志。

## 目录结构

```text
.
├── .github/workflows/      构建并发布镜像到 GHCR
├── server/                 FastAPI 后端
│   ├── api/                路由：auth / admin / webhook / health
│   ├── auth/               会话、密码、OAuth2、WebAuthn
│   ├── adapters/           钉钉 / 企业微信 / 飞书消息解析
│   ├── services/           QQ 客户端、频控、审计
│   └── db/                 模型、会话、加密、启动引导
├── web/                    Next.js 控制台
│   ├── app/(console)/      概览 / 机器人 / 日志 / 环境 / 用户 / 安全
│   └── lib/                类型、请求封装、通行密钥
├── alembic/                数据库迁移
├── deploy/                 容器入口与 supervisord 配置
├── tests/                  pytest 测试
├── Dockerfile
└── docker-compose.yml
```

## 安全建议

- 生产环境务必设置 `APP_SECRET_KEY`，密钥丢失将无法解密已入库的敏感字段。
- 使用 HTTPS 并将 `COOKIE_SECURE` 设为 `true`；`PUBLIC_BASE_URL` 填写真实对外地址，保证 OAuth 回调与 Webhook 地址正确。
- 不要将 MySQL 端口暴露到公网（compose 未映射 3306）。
- Webhook token 具有推送权限，泄露后请在「机器人 → 通道」中立即轮换。
- 邀请码按需签发并限定邮箱与有效期，注册入口用完即关。

## 已知限制

- 附件（图片 / 文件 / 语音）不会下发到 QQ：需要先调用 QQ 富媒体上传接口，当前未实现。
- 飞书新版 schema 2.0 卡片的 `card.body.elements` 未解析（旧版 `card.elements` 正常）。
- 钉钉 `audio` / `file` / `picture` 类型未支持。
- 入站使用自建 `X-Webhook-Token`，不校验平台签名（钉钉 sign、飞书 sign / verification token）；适合由用户侧将平台格式请求转发到本服务。
- 真实 QQ 推送与 OAuth2 第三方登录需要有效凭据，自动化测试仅覆盖到打桩层。

## 许可证

本项目基于 [GNU Affero General Public License v3.0](./LICENSE)（AGPL-3.0）开源，Copyright (c) 2026 CaiSre。

AGPL-3.0 是强 copyleft 许可证：修改并分发本项目，或将其作为网络服务对外提供时，需要以同一许可证公开对应源码。内部自用、不对外提供服务的部署不受额外约束。
