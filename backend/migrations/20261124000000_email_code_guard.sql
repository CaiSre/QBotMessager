-- 发码串行化：同一 (email, purpose) 的签发在这张表的行锁上排队，
-- 使冷却与小时配额的「读-判断-写入」在并发请求下不会被互相绕过。
-- 行本身不存状态，只作互斥用；条件写（INSERT ... ON DUPLICATE KEY UPDATE）
-- 让重复请求在已有行上等待前一个事务提交。
CREATE TABLE IF NOT EXISTS email_code_guards (
  email VARCHAR(255) NOT NULL,
  purpose VARCHAR(32) NOT NULL,
  PRIMARY KEY (email, purpose)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
