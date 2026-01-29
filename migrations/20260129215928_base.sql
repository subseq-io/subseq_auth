CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT NOT NULL UNIQUE,
    details JSONB,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth.users (email);

CREATE TABLE IF NOT EXISTS auth.access_roles (
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name)
);

CREATE INDEX IF NOT EXISTS idx_auth_access_roles_user_id ON auth.access_roles (user_id);

CREATE TABLE IF NOT EXISTS auth.groups (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    details JSONB,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_groups_display_name ON auth.groups (display_name);

CREATE TABLE IF NOT EXISTS auth.group_memberships (
    group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_group_memberships_group_id ON auth.group_memberships (group_id);
CREATE INDEX IF NOT EXISTS idx_auth_group_memberships_user_id ON auth.group_memberships (user_id);

CREATE TABLE IF NOT EXISTS auth.log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    action JSONB NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_log_user_id ON auth.log (user_id);
