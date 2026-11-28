-- 审计中心按动作过滤并按时间排序。
ALTER TABLE admin_audit_logs
    ADD KEY ix_admin_audit_logs_action_created (action, created_at);
