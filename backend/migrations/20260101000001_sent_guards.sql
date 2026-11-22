-- 幂等守卫表：替代原 Redis 的 `saq:sent:{key}`。
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
