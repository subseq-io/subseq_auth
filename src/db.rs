use once_cell::sync::Lazy;
use serde_json::{Value, json};
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::group_id::GroupId;
use crate::user_id::UserId;

pub static MIGRATOR: Lazy<Migrator> = Lazy::new(|| {
    let mut m = sqlx::migrate!("./migrations");
    m.set_ignore_missing(true);
    m
});

pub const GLOBAL_SCOPE: &str = "global";
pub const GLOBAL_SCOPE_ID: &str = "global";
pub const SUPER_ADMIN_ROLE: &str = "super_admin";
pub const GROUP_ADMIN_ROLE: &str = "group_admin";

pub async fn create_user_tables(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: Option<String>,
    pub email: String,
    pub details: Option<Value>,
}

impl UserRow {
    pub fn new(
        id: UserId,
        username: Option<String>,
        email: String,
        details: Option<Value>,
    ) -> Self {
        Self {
            id: id.0,
            username,
            email,
            details,
        }
    }

    pub fn table_name() -> &'static str {
        "auth.users"
    }

    pub fn columns() -> &'static str {
        "id, username, email, details"
    }

    pub async fn insert(pool: &PgPool, row: &UserRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(&row.username)
        .bind(&row.email)
        .bind(&row.details)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn get(pool: &PgPool, user_id: UserId) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE id = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_by_username(
        pool: &PgPool,
        username: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE username = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(username)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE email = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn set_details(
        pool: &PgPool,
        user_id: UserId,
        details: Option<Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET details = $1
            WHERE id = $2
            "#,
            Self::table_name()
        ))
        .bind(details)
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn deactivate(pool: &PgPool, user_id: UserId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET active = FALSE
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &PgPool, user_id: UserId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct UserRoleRow {
    pub user_id: Uuid,
    pub scope: String,
    pub scope_id: String,
    pub role_name: String,
}

impl UserRoleRow {
    pub fn new(user_id: UserId, scope: &str, scope_id: &str, role_name: &str) -> Self {
        Self {
            user_id: user_id.0,
            scope: scope.to_string(),
            scope_id: scope_id.to_string(),
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.user_roles"
    }

    pub fn columns() -> &'static str {
        "user_id, scope, scope_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &UserRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, scope, scope_id, role_name) DO NOTHING
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.user_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn revoke(pool: &PgPool, row: &UserRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(row.user_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn has_role(
        pool: &PgPool,
        user_id: UserId,
        scope: &str,
        scope_id: &str,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*)
            FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .bind(scope)
        .bind(scope_id)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn roles(pool: &PgPool, user_id: UserId) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE user_id = $1
            ORDER BY scope ASC, scope_id ASC, role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_all(pool)
        .await
    }

    pub async fn roles_in_scope(
        pool: &PgPool,
        user_id: UserId,
        scope: &str,
        scope_id: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
            ORDER BY role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .bind(scope)
        .bind(scope_id)
        .fetch_all(pool)
        .await
    }
}

/// Backward-compatible global user roles view on top of scoped user_roles.
#[derive(Debug, Clone, FromRow)]
pub struct AccessRoleRow {
    pub user_id: Uuid,
    pub role_name: String,
}

impl AccessRoleRow {
    pub fn new(user_id: UserId, role_name: &str) -> Self {
        Self {
            user_id: user_id.0,
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        UserRoleRow::table_name()
    }

    pub fn columns() -> &'static str {
        "user_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &AccessRoleRow) -> Result<(), sqlx::Error> {
        let scoped = UserRoleRow {
            user_id: row.user_id,
            scope: GLOBAL_SCOPE.to_string(),
            scope_id: GLOBAL_SCOPE_ID.to_string(),
            role_name: row.role_name.clone(),
        };
        UserRoleRow::allow(pool, &scoped).await
    }

    pub async fn revoke(pool: &PgPool, row: &AccessRoleRow) -> Result<(), sqlx::Error> {
        let scoped = UserRoleRow {
            user_id: row.user_id,
            scope: GLOBAL_SCOPE.to_string(),
            scope_id: GLOBAL_SCOPE_ID.to_string(),
            role_name: row.role_name.clone(),
        };
        UserRoleRow::revoke(pool, &scoped).await
    }

    pub async fn has_role(
        pool: &PgPool,
        user_id: UserId,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        UserRoleRow::has_role(pool, user_id, GLOBAL_SCOPE, GLOBAL_SCOPE_ID, role_name).await
    }

    pub async fn roles(pool: &PgPool, user_id: UserId) -> Result<Vec<Self>, sqlx::Error> {
        let rows =
            UserRoleRow::roles_in_scope(pool, user_id, GLOBAL_SCOPE, GLOBAL_SCOPE_ID).await?;
        Ok(rows
            .into_iter()
            .map(|row| Self {
                user_id: row.user_id,
                role_name: row.role_name,
            })
            .collect())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupRoleRow {
    pub group_id: Uuid,
    pub scope: String,
    pub scope_id: String,
    pub role_name: String,
}

impl GroupRoleRow {
    pub fn new(group_id: GroupId, scope: &str, scope_id: &str, role_name: &str) -> Self {
        Self {
            group_id: group_id.0,
            scope: scope.to_string(),
            scope_id: scope_id.to_string(),
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.group_roles"
    }

    pub fn columns() -> &'static str {
        "group_id, scope, scope_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &GroupRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (group_id, scope, scope_id, role_name) DO NOTHING
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.group_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn revoke(pool: &PgPool, row: &GroupRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(row.group_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn has_role(
        pool: &PgPool,
        group_id: GroupId,
        scope: &str,
        scope_id: &str,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*)
            FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(scope)
        .bind(scope_id)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn roles(pool: &PgPool, group_id: GroupId) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE group_id = $1
            ORDER BY scope ASC, scope_id ASC, role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .fetch_all(pool)
        .await
    }

    pub async fn roles_in_scope(
        pool: &PgPool,
        group_id: GroupId,
        scope: &str,
        scope_id: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
            ORDER BY role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(scope)
        .bind(scope_id)
        .fetch_all(pool)
        .await
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct RoleDelegationPolicyRow {
    pub scope: String,
    pub scope_id: String,
    pub admin_role: String,
    pub grantable_role: String,
}

impl RoleDelegationPolicyRow {
    pub fn new(scope: &str, scope_id: &str, admin_role: &str, grantable_role: &str) -> Self {
        Self {
            scope: scope.to_string(),
            scope_id: scope_id.to_string(),
            admin_role: admin_role.to_string(),
            grantable_role: grantable_role.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.role_delegation_policy"
    }

    pub fn columns() -> &'static str {
        "scope, scope_id, admin_role, grantable_role"
    }

    pub async fn allow(pool: &PgPool, row: &RoleDelegationPolicyRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (scope, scope_id, admin_role, grantable_role) DO NOTHING
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.admin_role)
        .bind(&row.grantable_role)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn revoke(pool: &PgPool, row: &RoleDelegationPolicyRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE scope = $1
              AND scope_id = $2
              AND admin_role = $3
              AND grantable_role = $4
            "#,
            Self::table_name()
        ))
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.admin_role)
        .bind(&row.grantable_role)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn admin_roles_for_grantable(
        pool: &PgPool,
        scope: &str,
        scope_id: &str,
        grantable_role: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(&format!(
            r#"
            SELECT DISTINCT admin_role
            FROM {}
            WHERE scope = $1
              AND grantable_role = $2
              AND (scope_id = $3 OR scope_id = $4)
            ORDER BY admin_role ASC
            "#,
            Self::table_name()
        ))
        .bind(scope)
        .bind(grantable_role)
        .bind(scope_id)
        .bind(GLOBAL_SCOPE_ID)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|row| row.0).collect())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RoleAssignmentTarget {
    User(UserId),
    Group(GroupId),
}

impl RoleAssignmentTarget {
    fn target_type(self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Group(_) => "group",
        }
    }

    fn target_id(self) -> String {
        match self {
            Self::User(user_id) => user_id.to_string(),
            Self::Group(group_id) => group_id.to_string(),
        }
    }
}

pub async fn is_super_admin(pool: &PgPool, user_id: UserId) -> Result<bool, sqlx::Error> {
    UserRoleRow::has_role(
        pool,
        user_id,
        GLOBAL_SCOPE,
        GLOBAL_SCOPE_ID,
        SUPER_ADMIN_ROLE,
    )
    .await
}

pub async fn user_is_group_admin_for_scope(
    pool: &PgPool,
    user_id: UserId,
    scope_id: &str,
) -> Result<bool, sqlx::Error> {
    match Uuid::parse_str(scope_id) {
        Ok(group_uuid) => {
            GroupMembershipRow::has_role(pool, GroupId(group_uuid), user_id, GROUP_ADMIN_ROLE).await
        }
        Err(_) => Ok(false),
    }
}

pub async fn user_has_effective_role(
    pool: &PgPool,
    user_id: UserId,
    scope: &str,
    scope_id: &str,
    role_name: &str,
) -> Result<bool, sqlx::Error> {
    if UserRoleRow::has_role(pool, user_id, scope, scope_id, role_name).await? {
        return Ok(true);
    }

    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM auth.group_memberships gm
        JOIN auth.group_roles gr
          ON gr.group_id = gm.group_id
        WHERE gm.user_id = $1
          AND gr.scope = $2
          AND gr.scope_id = $3
          AND gr.role_name = $4
        "#,
    )
    .bind(user_id.0)
    .bind(scope)
    .bind(scope_id)
    .bind(role_name)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}

pub async fn can_manage_role_assignment(
    pool: &PgPool,
    actor_user_id: UserId,
    scope: &str,
    scope_id: &str,
    grantable_role: &str,
) -> Result<bool, sqlx::Error> {
    if is_super_admin(pool, actor_user_id).await? {
        return Ok(true);
    }

    if scope != GLOBAL_SCOPE
        && scope_id != GLOBAL_SCOPE_ID
        && user_is_group_admin_for_scope(pool, actor_user_id, scope_id).await?
    {
        return Ok(true);
    }

    let admin_roles =
        RoleDelegationPolicyRow::admin_roles_for_grantable(pool, scope, scope_id, grantable_role)
            .await?;
    if admin_roles.is_empty() {
        return Ok(false);
    }

    for admin_role in admin_roles {
        if user_has_effective_role(pool, actor_user_id, scope, scope_id, &admin_role).await?
            || user_has_effective_role(pool, actor_user_id, scope, GLOBAL_SCOPE_ID, &admin_role)
                .await?
        {
            return Ok(true);
        }
    }

    Ok(false)
}

pub async fn user_has_effective_access(
    pool: &PgPool,
    user_id: UserId,
    scope: &str,
    scope_id: &str,
    role_name: &str,
) -> Result<bool, sqlx::Error> {
    if is_super_admin(pool, user_id).await? {
        return Ok(true);
    }

    if scope != GLOBAL_SCOPE
        && scope_id != GLOBAL_SCOPE_ID
        && user_is_group_admin_for_scope(pool, user_id, scope_id).await?
    {
        return Ok(true);
    }

    if user_has_effective_role(pool, user_id, scope, scope_id, role_name).await? {
        return Ok(true);
    }

    user_has_effective_role(pool, user_id, scope, GLOBAL_SCOPE_ID, role_name).await
}

pub async fn grant_role_assignment_with_audit(
    pool: &PgPool,
    actor_user_id: UserId,
    target: RoleAssignmentTarget,
    scope: &str,
    scope_id: &str,
    role_name: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let changed = match target {
        RoleAssignmentTarget::User(user_id) => {
            let result = sqlx::query(
                r#"
                INSERT INTO auth.user_roles (user_id, scope, scope_id, role_name)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, scope, scope_id, role_name) DO NOTHING
                "#,
            )
            .bind(user_id.0)
            .bind(scope)
            .bind(scope_id)
            .bind(role_name)
            .execute(&mut *tx)
            .await?;
            result.rows_affected() > 0
        }
        RoleAssignmentTarget::Group(group_id) => {
            let result = sqlx::query(
                r#"
                INSERT INTO auth.group_roles (group_id, scope, scope_id, role_name)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (group_id, scope, scope_id, role_name) DO NOTHING
                "#,
            )
            .bind(group_id.0)
            .bind(scope)
            .bind(scope_id)
            .bind(role_name)
            .execute(&mut *tx)
            .await?;
            result.rows_affected() > 0
        }
    };

    if changed {
        insert_role_audit_log(
            &mut tx,
            actor_user_id,
            "role_grant",
            target,
            scope,
            scope_id,
            role_name,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(changed)
}

pub async fn revoke_role_assignment_with_audit(
    pool: &PgPool,
    actor_user_id: UserId,
    target: RoleAssignmentTarget,
    scope: &str,
    scope_id: &str,
    role_name: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let changed = match target {
        RoleAssignmentTarget::User(user_id) => {
            let result = sqlx::query(
                r#"
                DELETE FROM auth.user_roles
                WHERE user_id = $1
                  AND scope = $2
                  AND scope_id = $3
                  AND role_name = $4
                "#,
            )
            .bind(user_id.0)
            .bind(scope)
            .bind(scope_id)
            .bind(role_name)
            .execute(&mut *tx)
            .await?;
            result.rows_affected() > 0
        }
        RoleAssignmentTarget::Group(group_id) => {
            let result = sqlx::query(
                r#"
                DELETE FROM auth.group_roles
                WHERE group_id = $1
                  AND scope = $2
                  AND scope_id = $3
                  AND role_name = $4
                "#,
            )
            .bind(group_id.0)
            .bind(scope)
            .bind(scope_id)
            .bind(role_name)
            .execute(&mut *tx)
            .await?;
            result.rows_affected() > 0
        }
    };

    if changed {
        insert_role_audit_log(
            &mut tx,
            actor_user_id,
            "role_revoke",
            target,
            scope,
            scope_id,
            role_name,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(changed)
}

async fn insert_role_audit_log(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_user_id: UserId,
    action_type: &str,
    target: RoleAssignmentTarget,
    scope: &str,
    scope_id: &str,
    role_name: &str,
) -> Result<(), sqlx::Error> {
    let action = json!({
        "type": action_type,
        "actor_user_id": actor_user_id.to_string(),
        "target_type": target.target_type(),
        "target_id": target.target_id(),
        "scope": scope,
        "scope_id": scope_id,
        "role_name": role_name,
    });

    sqlx::query(
        r#"
        INSERT INTO auth.log (id, user_id, action, timestamp)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(Some(actor_user_id.0))
    .bind(action)
    .bind(chrono::Utc::now().naive_utc())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub display_name: String,
    pub details: Option<Value>,
}

impl GroupRow {
    pub fn new(id: Uuid, details: Option<Value>, display_name: &str) -> Self {
        Self {
            id,
            display_name: display_name.to_string(),
            details,
        }
    }

    pub fn table_name() -> &'static str {
        "auth.groups"
    }

    pub fn columns() -> &'static str {
        "id, display_name, details"
    }

    pub async fn insert(pool: &PgPool, row: &GroupRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(&row.display_name)
        .bind(&row.details)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn get(pool: &PgPool, group_id: GroupId) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE id = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .fetch_optional(pool)
        .await
    }

    pub async fn set_details(
        pool: &PgPool,
        group_id: GroupId,
        details: Option<Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET details = $1
            WHERE id = $2
            "#,
            Self::table_name()
        ))
        .bind(details)
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn deactivate(pool: &PgPool, group_id: GroupId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET active = FALSE
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &PgPool, group_id: GroupId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupMembershipRow {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub role_name: String,
}

impl GroupMembershipRow {
    pub fn new(group_id: GroupId, user_id: UserId, role_name: &str) -> Self {
        Self {
            group_id: group_id.0,
            user_id: user_id.0,
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.group_memberships"
    }

    pub fn columns() -> &'static str {
        "group_id, user_id, role_name"
    }

    pub async fn add_member(pool: &PgPool, row: &GroupMembershipRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.group_id)
        .bind(row.user_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn remove_member(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
    ) -> Result<(), sqlx::Error> {
        Self::remove_member_with_inheritance(pool, group_id, user_id, None).await?;
        Ok(())
    }

    pub async fn remove_member_with_inheritance(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
        inheritor_user_id: Option<UserId>,
    ) -> Result<Option<UserId>, sqlx::Error> {
        let mut tx = pool.begin().await?;

        let leaving_role: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT role_name
            FROM auth.group_memberships
            WHERE group_id = $1 AND user_id = $2
            FOR UPDATE
            "#,
        )
        .bind(group_id.0)
        .bind(user_id.0)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((role_name,)) = leaving_role else {
            tx.commit().await?;
            return Ok(None);
        };

        let mut inherited_to = None;
        if role_name == GROUP_ADMIN_ROLE {
            let other_admin_exists: (bool,) = sqlx::query_as(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM auth.group_memberships
                    WHERE group_id = $1
                      AND user_id <> $2
                      AND role_name = $3
                )
                "#,
            )
            .bind(group_id.0)
            .bind(user_id.0)
            .bind(GROUP_ADMIN_ROLE)
            .fetch_one(&mut *tx)
            .await?;

            if !other_admin_exists.0 {
                let inheritor = if let Some(inheritor_user_id) = inheritor_user_id {
                    let is_member: (bool,) = sqlx::query_as(
                        r#"
                        SELECT EXISTS (
                            SELECT 1
                            FROM auth.group_memberships
                            WHERE group_id = $1 AND user_id = $2
                        )
                        "#,
                    )
                    .bind(group_id.0)
                    .bind(inheritor_user_id.0)
                    .fetch_one(&mut *tx)
                    .await?;
                    if is_member.0 {
                        Some(inheritor_user_id)
                    } else {
                        None
                    }
                } else {
                    sqlx::query_as::<_, (Uuid,)>(
                        r#"
                        SELECT user_id
                        FROM auth.group_memberships
                        WHERE group_id = $1
                          AND user_id <> $2
                        ORDER BY created_at ASC, user_id ASC
                        LIMIT 1
                        FOR UPDATE
                        "#,
                    )
                    .bind(group_id.0)
                    .bind(user_id.0)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|(id,)| UserId(id))
                };

                if let Some(inheritor_user_id) = inheritor {
                    sqlx::query(
                        r#"
                        UPDATE auth.group_memberships
                        SET role_name = $3
                        WHERE group_id = $1 AND user_id = $2
                        "#,
                    )
                    .bind(group_id.0)
                    .bind(inheritor_user_id.0)
                    .bind(GROUP_ADMIN_ROLE)
                    .execute(&mut *tx)
                    .await?;

                    inherited_to = Some(inheritor_user_id);
                }
            }
        }

        sqlx::query(
            r#"
            DELETE FROM auth.group_memberships
            WHERE group_id = $1 AND user_id = $2
            "#,
        )
        .bind(group_id.0)
        .bind(user_id.0)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(inherited_to)
    }

    pub async fn is_member(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*) FROM {}
            WHERE group_id = $1 AND user_id = $2
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(user_id.0)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn members(
        pool: &PgPool,
        group_id: GroupId,
        page: Option<(i64, i64)>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = if let Some((limit, offset)) = page {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE group_id = $1
                LIMIT $2 OFFSET $3
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, GroupMembershipRow>(&query)
                .bind(group_id.0)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        } else {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE group_id = $1
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, GroupMembershipRow>(&query)
                .bind(group_id.0)
                .fetch_all(pool)
                .await?
        };
        Ok(rows)
    }

    pub async fn groups_for_user(
        pool: &PgPool,
        user_id: UserId,
    ) -> Result<Vec<GroupRow>, sqlx::Error> {
        let rows = sqlx::query_as::<_, GroupRow>(&format!(
            r#"
            SELECT g.id, g.display_name, g.details
            FROM {} gm
            JOIN auth.groups g
              ON g.id = gm.group_id
            WHERE gm.user_id = $1
              AND g.active = TRUE
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn has_role(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*) FROM {}
            WHERE group_id = $1 AND user_id = $2 AND role_name = $3
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(user_id.0)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct LogRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: Value,
    pub timestamp: chrono::NaiveDateTime,
}

impl LogRow {
    pub fn new(user_id: UserId, action: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Some(user_id.0),
            action,
            timestamp: chrono::Utc::now().naive_utc(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.log"
    }

    pub fn columns() -> &'static str {
        "id, user_id, action, timestamp"
    }

    pub async fn insert(pool: &PgPool, row: &LogRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.action)
        .bind(row.timestamp)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn events_for_user(
        pool: &PgPool,
        user_id: UserId,
        page: Option<(i64, i64)>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = if let Some((limit, offset)) = page {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2 OFFSET $3
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, LogRow>(&query)
                .bind(user_id.0)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        } else {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE user_id = $1
                ORDER BY timestamp DESC
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, LogRow>(&query)
                .bind(user_id.0)
                .fetch_all(pool)
                .await?
        };
        Ok(rows)
    }
}
