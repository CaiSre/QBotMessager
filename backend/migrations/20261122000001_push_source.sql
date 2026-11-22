-- 新增用户自填的「推送来源」，用于区分 Webhook 的使用位置。
ALTER TABLE channels ADD COLUMN push_source VARCHAR(64) NOT NULL DEFAULT '' AFTER hook_type;
ALTER TABLE push_logs ADD COLUMN push_source VARCHAR(64) NOT NULL DEFAULT '' AFTER hook_type;
