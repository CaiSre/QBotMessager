-- 数据保留清理所需的更新时间与索引。
-- email_code_guards 原先只作互斥行，不记录状态；补 updated_at 后，
-- 长时间不再使用的 (email, purpose) 行才能安全回收。

ALTER TABLE email_code_guards
  ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,
  ADD KEY ix_email_code_guards_updated (updated_at);

ALTER TABLE sessions
  ADD KEY ix_sessions_expires (expires_at);

ALTER TABLE email_verification_codes
  ADD KEY ix_email_verification_codes_created (created_at);

ALTER TABLE admin_audit_logs
  ADD KEY ix_admin_audit_logs_created (created_at);
