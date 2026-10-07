-- RBAC vocabulary. Role and permission names are the contract Spring Security authorities are
-- built from, so the unique constraint on name is what keeps a seed from silently duplicating one.
CREATE TABLE roles (
    id   BIGSERIAL   PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    CONSTRAINT uq_roles_name UNIQUE (name)
);

CREATE TABLE permissions (
    id   BIGSERIAL   PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    CONSTRAINT uq_permissions_name UNIQUE (name)
);
