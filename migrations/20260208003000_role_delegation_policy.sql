CREATE TABLE IF NOT EXISTS auth.role_delegation_policy (
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    admin_role TEXT NOT NULL,
    grantable_role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scope, scope_id, admin_role, grantable_role),
    CHECK (scope <> ''),
    CHECK (scope_id <> ''),
    CHECK (admin_role <> ''),
    CHECK (grantable_role <> '')
);

CREATE INDEX IF NOT EXISTS idx_auth_role_delegation_policy_scope
    ON auth.role_delegation_policy (scope, scope_id);

CREATE INDEX IF NOT EXISTS idx_auth_role_delegation_policy_grantable
    ON auth.role_delegation_policy (scope, scope_id, grantable_role);

INSERT INTO auth.role_delegation_policy (scope, scope_id, admin_role, grantable_role)
VALUES
    ('global', 'global', 'super_admin', 'super_admin'),
    ('global', 'global', 'super_admin', 'group_admin')
ON CONFLICT (scope, scope_id, admin_role, grantable_role) DO NOTHING;
