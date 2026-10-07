-- Refresh tokens are stored hashed, never in plaintext (architecture 01-overview.md section 3).
-- Columns are exactly the ones that section specifies.
CREATE TABLE refresh_tokens (
    id         BIGSERIAL    PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    -- Width is generous on purpose: the hash algorithm is chosen in backlog 0004, and hex SHA-256
    -- (64), Base64 (44) and BCrypt (60) all have to fit without a second migration.
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    -- Refresh is a lookup by hash, so this constraint is both the index that lookup needs and the
    -- guarantee that one stored hash can never map to two users.
    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Covers "all tokens of this user", needed to revoke or clean up per account.
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
