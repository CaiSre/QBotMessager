-- 「平台」更名为「钩子类型」，字段命名为 hook_type。
ALTER TABLE channels RENAME COLUMN platform TO hook_type;
ALTER TABLE push_logs RENAME COLUMN platform TO hook_type;
