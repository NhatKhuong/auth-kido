-- Demo accounts, so the API can be logged into without a registration endpoint (there is none).
-- Separate from V6 on purpose: V6 is system data that production would keep, this file is sample
-- data that can be deleted by a later migration without touching the RBAC vocabulary.
--
-- Passwords are BCrypt hashes (strength 10) and never appear in plaintext here. The matching
-- plaintext for local testing is documented in .env.example.
INSERT INTO users (username, password_hash) VALUES
    ('admin', '$2a$10$FFle.qcCJM4N.zvD19uUSOvD6m3ehS6cTSLKiNLHvXnqRV7UZq2oq'),
    ('user',  '$2a$10$oiu01JhbSLq5UDeuNKNwTO7bxyYizwDuUyiuGj9KMfLAz8co5HV5e');

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
         JOIN roles r ON r.name = 'ROLE_ADMIN'
WHERE u.username = 'admin';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
         JOIN roles r ON r.name = 'ROLE_USER'
WHERE u.username = 'user';
