-- 持久化通行密钥注册时的用户验证结果与策略。
ALTER TABLE webauthn_credentials
    ADD COLUMN user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN registration_policy VARCHAR(16) NOT NULL DEFAULT 'preferred';
