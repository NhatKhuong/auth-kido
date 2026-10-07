-- System seed: the role and permission names are a contract. @PreAuthorize("hasAuthority('...')")
-- in backlog 0006/0007 refers to these exact strings, so renaming one breaks authorization.
-- Kept separate from the demo accounts (V7) so this data can stay while demo users are dropped.
INSERT INTO roles (name) VALUES
    ('ROLE_USER'),
    ('ROLE_ADMIN');

INSERT INTO permissions (name) VALUES
    ('ACCOUNT_READ'),
    ('PASSWORD_CHANGE'),
    ('USER_READ'),
    ('USER_MANAGE');

-- Resolved by name rather than by literal id: the ids come from a sequence and must not be
-- assumed here.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.name IN ('ACCOUNT_READ', 'PASSWORD_CHANGE')
WHERE r.name = 'ROLE_USER';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.name IN ('ACCOUNT_READ', 'PASSWORD_CHANGE', 'USER_READ', 'USER_MANAGE')
WHERE r.name = 'ROLE_ADMIN';
