-- 初始 schema：13 张表。
--
-- 写法说明：全部使用 CREATE TABLE IF NOT EXISTS，索引与唯一约束**内联**在建表语句里
-- （MySQL 不支持 CREATE INDEX IF NOT EXISTS，因此索引随建表原子创建）。
-- 外键约束名统一 fk_<table>_<column>_<referred_table>。

CREATE TABLE IF NOT EXISTS users (
  id BIGINT NOT NULL AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  name VARCHAR(128) NOT NULL DEFAULT '',
  password_hash VARCHAR(255) NULL,
  role VARCHAR(16) NOT NULL DEFAULT 'user',
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  -- 函数索引：用户名忽略大小写唯一（MySQL 8.0.13+）
  UNIQUE KEY uq_users_name_lower ((lower(name)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_identities (
  id BIGINT NOT NULL AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  provider VARCHAR(64) NOT NULL,
  provider_user_id VARCHAR(255) NOT NULL,
  provider_login VARCHAR(255) NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_identity_provider_uid (provider, provider_user_id),
  KEY ix_auth_identities_user_id (user_id),
  CONSTRAINT fk_auth_identities_user_id_users FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id BIGINT NOT NULL AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  -- MySQL 的 BLOB 不能直接建唯一索引，凭据 ID 用 VARBINARY
  credential_id VARBINARY(255) NOT NULL,
  public_key BLOB NOT NULL,
  sign_count BIGINT NOT NULL DEFAULT 0,
  aaguid VARCHAR(64) NULL,
  transports JSON NULL,
  device_type VARCHAR(32) NULL,
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  label VARCHAR(64) NOT NULL DEFAULT '',
  last_used_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_webauthn_credentials_credential_id (credential_id),
  KEY ix_webauthn_credentials_user_id (user_id),
  CONSTRAINT fk_webauthn_credentials_user_id_users FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
  id BIGINT NOT NULL AUTO_INCREMENT,
  token_hash VARCHAR(64) NOT NULL,
  user_id BIGINT NOT NULL,
  ip VARCHAR(64) NULL,
  user_agent VARCHAR(255) NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_token_hash (token_hash),
  KEY ix_sessions_user_id (user_id),
  CONSTRAINT fk_sessions_user_id_users FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS invite_codes (
  id BIGINT NOT NULL AUTO_INCREMENT,
  code VARCHAR(64) NOT NULL,
  email VARCHAR(255) NULL,
  max_uses INT NOT NULL DEFAULT 1,
  used_count INT NOT NULL DEFAULT 0,
  expires_at DATETIME NULL,
  revoked_at DATETIME NULL,
  created_by BIGINT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_invite_codes_code (code),
  CONSTRAINT fk_invite_codes_created_by_users FOREIGN KEY (created_by) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS bot_profiles (
  id BIGINT NOT NULL AUTO_INCREMENT,
  owner_user_id BIGINT NOT NULL,
  name VARCHAR(128) NOT NULL,
  qq_appid VARCHAR(128) NOT NULL,
  qq_app_secret TEXT NOT NULL,
  qq_host VARCHAR(255) NOT NULL DEFAULT 'https://api.bot.qq.com',
  default_openids JSON NOT NULL,
  default_group_openid VARCHAR(128) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_bot_profiles_owner_user_id (owner_user_id),
  CONSTRAINT fk_bot_profiles_owner_user_id_users FOREIGN KEY (owner_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS channels (
  id BIGINT NOT NULL AUTO_INCREMENT,
  bot_profile_id BIGINT NOT NULL,
  platform VARCHAR(32) NOT NULL,
  webhook_token VARCHAR(64) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  extra JSON NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_channels_webhook_token (webhook_token),
  KEY ix_channels_bot_profile_id (bot_profile_id),
  CONSTRAINT fk_channels_bot_profile_id_bot_profiles FOREIGN KEY (bot_profile_id) REFERENCES bot_profiles (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS push_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  owner_user_id BIGINT NOT NULL,
  channel_id BIGINT NULL,
  bot_profile_id BIGINT NULL,
  platform VARCHAR(32) NOT NULL,
  source_msgtype VARCHAR(32) NOT NULL,
  target VARCHAR(255) NOT NULL,
  qq_msg_type INT NULL,
  content_preview TEXT NOT NULL DEFAULT (''),
  content_len INT NOT NULL DEFAULT 0,
  status VARCHAR(16) NOT NULL,
  error_code VARCHAR(64) NULL,
  error_message TEXT NULL,
  duration_ms DOUBLE NOT NULL DEFAULT 0,
  request_id VARCHAR(64) NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_push_logs_owner_created (owner_user_id, created_at),
  KEY ix_push_logs_created (created_at),
  KEY ix_push_logs_status (status),
  CONSTRAINT fk_push_logs_owner_user_id_users FOREIGN KEY (owner_user_id) REFERENCES users (id),
  -- 机器人/通道删除后日志仍保留，归属判断不依赖它们
  CONSTRAINT fk_push_logs_channel_id_channels FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE SET NULL,
  CONSTRAINT fk_push_logs_bot_profile_id_bot_profiles FOREIGN KEY (bot_profile_id) REFERENCES bot_profiles (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS email_verification_codes (
  id BIGINT NOT NULL AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  purpose VARCHAR(32) NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  attempts INT NOT NULL DEFAULT 0,
  ip VARCHAR(64) NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_email_verification_codes_email (email),
  KEY ix_email_verification_codes_purpose (purpose)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  actor_user_id BIGINT NULL,
  action VARCHAR(64) NOT NULL,
  target_type VARCHAR(64) NULL,
  target_id VARCHAR(128) NULL,
  detail JSON NULL,
  ip VARCHAR(64) NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  KEY ix_audit_actor_created (actor_user_id, created_at),
  CONSTRAINT fk_admin_audit_logs_actor_user_id_users FOREIGN KEY (actor_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS oauth_providers (
  id BIGINT NOT NULL AUTO_INCREMENT,
  `key` VARCHAR(64) NOT NULL,
  display_name VARCHAR(128) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  client_secret TEXT NOT NULL,
  authorization_url VARCHAR(512) NOT NULL,
  token_url VARCHAR(512) NOT NULL,
  userinfo_url VARCHAR(512) NOT NULL,
  scopes VARCHAR(255) NOT NULL DEFAULT '',
  email_field VARCHAR(64) NOT NULL DEFAULT 'email',
  id_field VARCHAR(64) NOT NULL DEFAULT 'id',
  name_field VARCHAR(64) NOT NULL DEFAULT 'name',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  -- 该提供方的邮箱是否可信（提供方已验证过邮箱所有权）；
  -- 不可信时不会自动关联同邮箱的本地账号，避免冒名登录接管
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_oauth_providers_key (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_settings (
  `key` VARCHAR(64) NOT NULL,
  `value` TEXT NOT NULL DEFAULT (''),
  updated_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 幂等守卫表。
--
-- 键 = {request_id}:{target_label}，target_label ∈ group:{group_openid} / user:{openid}；
-- 用 INSERT IGNORE 判首次，读取失败按「未发送」处理；
-- 过期行由 worker 内的定时任务清理。

CREATE TABLE IF NOT EXISTS sent_guards (
  id BIGINT NOT NULL AUTO_INCREMENT,
  guard_key VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sent_guards_guard_key (guard_key),
  KEY ix_sent_guards_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
