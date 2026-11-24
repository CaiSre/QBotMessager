-- Webhook token 只保存哈希：库内不再保留明文，令牌仅在创建/轮换时一次性展示。
-- 既有明文就地改写为 SHA-256 小写十六进制，与会话 token 的入库形式一致。
ALTER TABLE channels RENAME COLUMN webhook_token TO webhook_token_hash;
UPDATE channels SET webhook_token_hash = SHA2(webhook_token_hash, 256);
ALTER TABLE channels RENAME INDEX uq_channels_webhook_token TO uq_channels_webhook_token_hash;
