use std::sync::Arc;

use crate::prelude::{AuthenticatedUser, GroupId, RejectReason, UserId, ValidatesIdentity};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cookie::SameSite;
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::db::{
    AccessRoleRow, GroupMembershipRow, GroupRoleRow, GroupRow, LogRow, RoleAssignmentTarget,
    UserRoleRow, UserRow, GLOBAL_SCOPE, GLOBAL_SCOPE_ID, SUPER_ADMIN_ROLE,
    can_manage_role_assignment, grant_role_assignment_with_audit, is_super_admin,
    revoke_role_assignment_with_audit, user_is_group_admin_for_scope,
};

/// Provides access to the database connection pool.
pub trait HasPool {
    fn pool(&self) -> Arc<sqlx::PgPool>;
}

/// Announces user-related events to the application.
///
/// This allows the application to hook into user lifecycle events for logging, notifications, or
/// additional processing.
///
/// Spawn a task or emit an event if you need async processing.
pub trait AnnouncesUserEvents {
    fn announce_new_user(&self, user: &User);
    fn announce_user_deactivation(&self, user_id: UserId);
    fn announce_user_update(&self, user: &User);
    fn announce_user_group_join(&self, user_id: UserId, group_id: GroupId);
    fn announce_user_group_leave(&self, user_id: UserId, group_id: GroupId);
}

pub trait AuthApp: ValidatesIdentity + HasPool + AnnouncesUserEvents {}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: UserId,
    pub username: Option<String>,
    pub email: String,
    pub details: Option<Value>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: UserId(row.id),
            username: row.username,
            email: row.email,
            details: row.details,
        }
    }
}

/// Handler to get or create the authenticated user's record.
///
/// If the user does not exist in the database, create a new record using the information from the
/// AuthenticatedUser.
///
/// This serves as a new user insertion point when first seen from the identity provider.
pub async fn self_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let user = UserRow::get(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    if let Some(user) = user {
        Ok(Json(User::from(user)))
    } else {
        // Must have a valid email from the identity provider.
        let email = auth_user
            .email()
            .ok_or_else(|| RejectReason::bad_request("Email is required"))?;

        // Create a user record if it doesn't exist.
        let new_user = UserRow::new(auth_user.id(), auth_user.username(), email, None);
        UserRow::insert(&pool, &new_user)
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?;

        let user = User::from(new_user.clone());
        app.announce_new_user(&user);

        Ok(Json(user))
    }
}

/// Handler to update the authenticated user's record.
///
/// Stores arbitrary JSON details about the user.
pub async fn self_update_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let details = Some(payload);
    UserRow::set_details(&pool, auth_user.id(), details)
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;

    let user_row = UserRow::get(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?
        .ok_or_else(|| RejectReason::not_found("User not found"))?;
    let user = User::from(user_row);

    app.announce_user_update(&user);
    Ok(Json(user))
}

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
}

impl From<GroupRow> for Group {
    fn from(row: GroupRow) -> Self {
        Self {
            id: GroupId(row.id),
            name: row.display_name,
        }
    }
}

/// Handler to get the authenticated user's groups.
///
/// Groups are used as a way to organize users, assign permissions, and manage payments within the
/// system. Although you could use a group for RBAC purposes, we provide a separate permissions
/// endpoint to allow for role assignments without the JOIN overhead of groups.
pub async fn self_groups_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let groups = GroupMembershipRow::groups_for_user(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(Json(
        groups.into_iter().map(Group::from).collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct Role {
    pub name: String,
}

impl From<AccessRoleRow> for Role {
    fn from(row: AccessRoleRow) -> Self {
        Self {
            name: row.role_name,
        }
    }
}

/// Retrieve top-level permissions for the authenticated user.
///
/// These can be whatever is necessary to determine the user's capabilities in the system.
/// It is suggested to use a naming scheme that allows for easy parsing and understanding of the
/// role's scope.
///
/// E.g., "system::admin", "group::<id>::owner", etc.
///
/// None of the endpoints here assume any specific roles; it's up to the application to interpret
/// them and add additional endpoints as necessary to perform actions based on these roles.
pub async fn self_permissions_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let roles = AccessRoleRow::roles(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(Json(roles.into_iter().map(Role::from).collect::<Vec<_>>()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "target_type", rename_all = "snake_case")]
pub enum RoleTargetContent {
    User { user_id: UserId },
    Group { group_id: GroupId },
}

impl RoleTargetContent {
    fn assignment_target(&self) -> RoleAssignmentTarget {
        match self {
            Self::User { user_id } => RoleAssignmentTarget::User(*user_id),
            Self::Group { group_id } => RoleAssignmentTarget::Group(*group_id),
        }
    }

    fn target_user_id(&self) -> Option<UserId> {
        match self {
            Self::User { user_id } => Some(*user_id),
            Self::Group { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleChangeContent {
    #[serde(flatten)]
    pub target: RoleTargetContent,
    pub scope: String,
    pub scope_id: String,
    pub role_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleChangeResult {
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedRole {
    pub scope: String,
    pub scope_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolesResponse {
    pub target_type: String,
    pub target_id: String,
    pub roles: Vec<ScopedRole>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RolesQuery {
    pub target_type: Option<String>,
    pub user_id: Option<UserId>,
    pub group_id: Option<GroupId>,
    pub scope: Option<String>,
    pub scope_id: Option<String>,
}

enum RoleMutationKind {
    Grant,
    Revoke,
}

async fn mutate_role_assignment<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    payload: RoleChangeContent,
    kind: RoleMutationKind,
) -> Result<Json<RoleChangeResult>, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let actor_user_id = auth_user.id();

    let scope = payload.scope.trim();
    let scope_id = payload.scope_id.trim();
    let role_name = payload.role_name.trim();
    if scope.is_empty() || scope_id.is_empty() || role_name.is_empty() {
        return Err(RejectReason::bad_request(
            "scope, scope_id, and role_name are required",
        ));
    }
    if role_name == SUPER_ADMIN_ROLE && (scope != GLOBAL_SCOPE || scope_id != GLOBAL_SCOPE_ID) {
        return Err(RejectReason::bad_request(
            "super_admin can only be assigned at scope=global and scope_id=global",
        ));
    }

    let actor_is_super_admin = is_super_admin(&pool, actor_user_id)
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    if matches!(kind, RoleMutationKind::Grant)
        && payload.target.target_user_id() == Some(actor_user_id)
        && !actor_is_super_admin
    {
        return Err(RejectReason::forbidden(
            actor_user_id,
            "Non-super-admin users cannot grant roles to themselves",
        ));
    }

    let can_manage = if actor_is_super_admin {
        true
    } else {
        can_manage_role_assignment(&pool, actor_user_id, scope, scope_id, role_name)
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?
    };
    if !can_manage {
        return Err(RejectReason::forbidden(
            actor_user_id,
            "Missing delegated role-management permission for this scope",
        ));
    }

    let changed = match kind {
        RoleMutationKind::Grant => {
            grant_role_assignment_with_audit(
                &pool,
                actor_user_id,
                payload.target.assignment_target(),
                scope,
                scope_id,
                role_name,
            )
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?
        }
        RoleMutationKind::Revoke => {
            revoke_role_assignment_with_audit(
                &pool,
                actor_user_id,
                payload.target.assignment_target(),
                scope,
                scope_id,
                role_name,
            )
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?
        }
    };

    Ok(Json(RoleChangeResult { changed }))
}

pub async fn role_grant_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RoleChangeContent>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    mutate_role_assignment(app, auth_user, payload, RoleMutationKind::Grant).await
}

pub async fn role_revoke_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<RoleChangeContent>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    mutate_role_assignment(app, auth_user, payload, RoleMutationKind::Revoke).await
}

pub async fn roles_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Query(query): Query<RolesQuery>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    if query.scope.is_some() != query.scope_id.is_some() {
        return Err(RejectReason::bad_request(
            "scope and scope_id must be provided together",
        ));
    }

    let pool = app.pool();
    let actor_user_id = auth_user.id();
    let actor_is_super_admin = is_super_admin(&pool, actor_user_id)
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    let scope = query.scope.as_deref();
    let scope_id = query.scope_id.as_deref();

    match query.target_type.as_deref().unwrap_or("user") {
        "user" => {
            if query.group_id.is_some() {
                return Err(RejectReason::bad_request(
                    "group_id cannot be used when target_type=user",
                ));
            }

            let user_id = query.user_id.unwrap_or(actor_user_id);
            if user_id != actor_user_id && !actor_is_super_admin {
                return Err(RejectReason::forbidden(
                    actor_user_id,
                    "Only super_admin can read another user's role assignments",
                ));
            }

            let rows = if let (Some(scope), Some(scope_id)) = (scope, scope_id) {
                UserRoleRow::roles_in_scope(&pool, user_id, scope, scope_id)
                    .await
                    .map_err(|_| RejectReason::database("Failed to reach database"))?
            } else {
                UserRoleRow::roles(&pool, user_id)
                    .await
                    .map_err(|_| RejectReason::database("Failed to reach database"))?
            };

            let roles = rows
                .into_iter()
                .map(|row| ScopedRole {
                    scope: row.scope,
                    scope_id: row.scope_id,
                    name: row.role_name,
                })
                .collect::<Vec<_>>();

            Ok(Json(RolesResponse {
                target_type: "user".to_string(),
                target_id: user_id.to_string(),
                roles,
            }))
        }
        "group" => {
            if query.user_id.is_some() {
                return Err(RejectReason::bad_request(
                    "user_id cannot be used when target_type=group",
                ));
            }
            let group_id = query
                .group_id
                .ok_or_else(|| RejectReason::bad_request("group_id is required for group roles"))?;

            let actor_is_group_admin = if actor_is_super_admin {
                true
            } else {
                user_is_group_admin_for_scope(&pool, actor_user_id, &group_id.to_string())
                    .await
                    .map_err(|_| RejectReason::database("Failed to reach database"))?
            };
            if !actor_is_group_admin {
                return Err(RejectReason::forbidden(
                    actor_user_id,
                    "Only group_admin or super_admin can read group role assignments",
                ));
            }

            let rows = if let (Some(scope), Some(scope_id)) = (scope, scope_id) {
                GroupRoleRow::roles_in_scope(&pool, group_id, scope, scope_id)
                    .await
                    .map_err(|_| RejectReason::database("Failed to reach database"))?
            } else {
                GroupRoleRow::roles(&pool, group_id)
                    .await
                    .map_err(|_| RejectReason::database("Failed to reach database"))?
            };

            let roles = rows
                .into_iter()
                .map(|row| ScopedRole {
                    scope: row.scope,
                    scope_id: row.scope_id,
                    name: row.role_name,
                })
                .collect::<Vec<_>>();

            Ok(Json(RolesResponse {
                target_type: "group".to_string(),
                target_id: group_id.to_string(),
                roles,
            }))
        }
        _ => Err(RejectReason::bad_request(
            "target_type must be either `user` or `group`",
        )),
    }
}

/// Allow the user to deactivate their own account. This isn't a deletion, but you can add that as
/// a follow-up action by database scan on a schedule for GDPR compliance or similar.
pub async fn self_deactivate_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    UserRow::deactivate(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    app.announce_user_deactivation(auth_user.id());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveGroupContent {
    pub group_id: GroupId,
    pub inheritor_user_id: Option<UserId>,
}

/// Allow the user to leave a group they are a member of.
///
/// We don't have a handler for adding users to groups because an application may want to enforce
/// invitations or other rules that keep both the group and users safe from abuse.
pub async fn self_leave_group_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<LeaveGroupContent>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    if payload.inheritor_user_id == Some(auth_user.id()) {
        return Err(RejectReason::bad_request(
            "inheritor_user_id cannot be the same as the user leaving the group",
        ));
    }
    if let Some(inheritor_user_id) = payload.inheritor_user_id {
        let inheritor_is_member =
            GroupMembershipRow::is_member(&pool, payload.group_id, inheritor_user_id)
                .await
                .map_err(|_| RejectReason::database("Failed to reach database"))?;
        if !inheritor_is_member {
            return Err(RejectReason::bad_request(
                "inheritor_user_id must be an existing group member",
            ));
        }
    }

    let was_member = GroupMembershipRow::is_member(&pool, payload.group_id, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    if !was_member {
        return Ok(StatusCode::NO_CONTENT);
    }

    let inherited_admin = GroupMembershipRow::remove_member_with_inheritance(
        &pool,
        payload.group_id,
        auth_user.id(),
        payload.inheritor_user_id,
    )
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;

    let leave_log = LogRow::new(
        auth_user.id(),
        json!({
            "type": "group_leave",
            "group_id": payload.group_id.to_string(),
            "user_id": auth_user.id().to_string(),
        }),
    );
    LogRow::insert(&pool, &leave_log)
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;

    if let Some(inherited_admin_user_id) = inherited_admin {
        let inheritance_log = LogRow::new(
            auth_user.id(),
            json!({
                "type": "group_admin_inherited",
                "group_id": payload.group_id.to_string(),
                "from_user_id": auth_user.id().to_string(),
                "to_user_id": inherited_admin_user_id.to_string(),
            }),
        );
        LogRow::insert(&pool, &inheritance_log)
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?;
    }

    app.announce_user_group_leave(auth_user.id(), payload.group_id);
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes<S>(store: MemoryStore) -> Router<S>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /auth/me [GET,PUT]");
    tracing::info!("Registering route /auth/me/groups [GET]");
    tracing::info!("Registering route /auth/me/permissions [GET]");
    tracing::info!("Registering route /auth/me/deactivate [POST]");
    tracing::info!("Registering route /auth/me/leave [POST]");
    tracing::info!("Registering route /auth/roles [GET]");
    tracing::info!("Registering route /auth/roles/grant [POST]");
    tracing::info!("Registering route /auth/roles/revoke [POST]");
    let layer = SessionManagerLayer::new(store)
        .with_secure(false)
        .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));
    Router::new()
        .route(
            "/auth/me",
            get(self_handler::<S>).put(self_update_handler::<S>),
        )
        .route("/auth/me/groups", get(self_groups_handler::<S>))
        .route("/auth/me/permissions", get(self_permissions_handler::<S>))
        .route("/auth/me/deactivate", post(self_deactivate_handler::<S>))
        .route("/auth/me/leave", post(self_leave_group_handler::<S>))
        .route("/auth/roles", get(roles_handler::<S>))
        .route("/auth/roles/grant", post(role_grant_handler::<S>))
        .route("/auth/roles/revoke", post(role_revoke_handler::<S>))
        .layer(layer)
}
