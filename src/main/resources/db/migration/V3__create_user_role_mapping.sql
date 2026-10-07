-- Join table for User N:N Role. The composite primary key makes assigning the same role twice
-- impossible; ON DELETE CASCADE means deleting a user never leaves dangling grants.
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

-- The primary key already indexes (user_id, role_id); this covers lookups that start from a role.
CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);
