-- Account credentials. Deliberately minimal: only the columns the API contracts actually read
-- (id, username) plus the password hash. Migrations are forward-only, so an unused column here
-- would be permanent debt; profile fields are added by the ticket that needs them.
CREATE TABLE users (
    id            BIGSERIAL    PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL,
    -- BCrypt output is 60 chars; the extra room lets the encoder change without a migration.
    password_hash VARCHAR(100) NOT NULL,
    CONSTRAINT uq_users_username UNIQUE (username)
);
