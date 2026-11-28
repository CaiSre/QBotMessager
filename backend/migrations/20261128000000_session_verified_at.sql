-- 敏感操作（绑定/删除登录凭据）要求近期的身份验证：
-- 登录或显式验证后写入 verified_at，超过窗口的会话需重新验证。
ALTER TABLE sessions ADD COLUMN verified_at DATETIME NULL AFTER user_agent;
UPDATE sessions SET verified_at = created_at WHERE verified_at IS NULL;
