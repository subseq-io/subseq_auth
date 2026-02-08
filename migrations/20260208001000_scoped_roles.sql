CREATE TABLE IF NOT EXISTS auth.user_roles (
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, scope, scope_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_auth_user_roles_user_scope
    ON auth.user_roles (user_id, scope, scope_id);

CREATE TABLE IF NOT EXISTS auth.group_roles (
    group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, scope, scope_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_auth_group_roles_group_scope
    ON auth.group_roles (group_id, scope, scope_id);

INSERT INTO auth.user_roles (user_id, scope, scope_id, role_name)
SELECT user_id, 'global', 'global', role_name
FROM auth.access_roles
ON CONFLICT (user_id, scope, scope_id, role_name) DO NOTHING;

DROP TABLE IF EXISTS auth.access_roles;
