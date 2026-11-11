-- Built-in roles and permissions for the admin app. Add more with new migrations (or
-- from the admin app; non-system roles are editable there).

INSERT INTO permissions (key, resource, action, description) VALUES
    ('users.read',         'users',       'read',    'See users and their profiles'),
    ('users.update',       'users',       'update',  'Edit usernames, profile names and emails'),
    ('users.suspend',      'users',       'suspend', 'Suspend and restore accounts'),
    ('users.delete',       'users',       'delete',  'Delete accounts'),
    ('sessions.read',      'sessions',    'read',    'See signed-in sessions'),
    ('sessions.revoke',    'sessions',    'revoke',  'Sign users out'),
    ('devices.read',       'devices',     'read',    'See devices'),
    ('devices.revoke',     'devices',     'revoke',  'Remove devices'),
    ('connections.read',   'connections', 'read',    'See connection history'),
    ('relays.read',        'relays',      'read',    'See live relays and traffic'),
    ('roles.read',         'roles',       'read',    'See roles and permissions'),
    ('roles.manage',       'roles',       'manage',  'Create, edit and assign roles'),
    ('audit.read',         'audit',       'read',    'Read the audit log')
ON CONFLICT (key) DO NOTHING;

INSERT INTO roles (key, name, description, is_system, is_default) VALUES
    ('admin',     'Administrator', 'Everything, including roles',            true, false),
    ('moderator', 'Moderator',     'Handle users, sessions and devices',     true, false),
    ('support',   'Support',       'Read-only access to help users',         true, false),
    ('user',      'User',          'Regular account (no admin permissions)', true, true)
ON CONFLICT (key) DO NOTHING;

-- admin: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.key = 'admin'
ON CONFLICT DO NOTHING;

-- moderator
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.key IN (
    'users.read', 'users.update', 'users.suspend', 'sessions.read', 'sessions.revoke',
    'devices.read', 'devices.revoke', 'connections.read', 'audit.read'
) WHERE r.key = 'moderator'
ON CONFLICT DO NOTHING;

-- support (read-only)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.key IN (
    'users.read', 'sessions.read', 'devices.read', 'connections.read'
) WHERE r.key = 'support'
ON CONFLICT DO NOTHING;
