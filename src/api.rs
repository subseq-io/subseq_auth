use std::sync::Arc;

use crate::group_id::GroupId;
use crate::prelude::{AuthenticatedUser, RejectReason, ValidatesIdentity};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cookie::SameSite;
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::db::{AccessRoleRow, GroupMembershipRow, GroupRow, UserRow};

/// Provides access to the database connection pool.
pub trait HasPool {
    fn pool(&self) -> Arc<sqlx::PgPool>;
}

/// Announces user-related events to the application.
///
/// This allows the application to hook into user lifecycle events for logging, notifications, or
/// additional processing.
pub trait AnnouncesUserEvents {
    fn announce_new_user(&self, user: &User);
    fn announce_user_deactivation(&self, user_id: uuid::Uuid);
    fn announce_user_update(&self, user: &User);
    fn announce_user_group_join(&self, user_id: uuid::Uuid, group_id: GroupId);
    fn announce_user_group_leave(&self, user_id: uuid::Uuid, group_id: GroupId);
}

pub trait AuthApp: ValidatesIdentity + HasPool + AnnouncesUserEvents {}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: Option<String>,
    pub email: String,
    pub details: Option<Value>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
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
        let new_user = UserRow::new(
            auth_user.id(),
            auth_user.username(),
            email,
            None,
        );
        UserRow::insert(&pool, &new_user)
            .await
            .map_err(|_| RejectReason::database("Failed to reach database"))?;
        Ok(Json(User::from(new_user)))
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
    Ok(StatusCode::NO_CONTENT)
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
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveGroupContent {
    pub group_id: String,
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
    let group_id = uuid::Uuid::parse_str(&payload.group_id)
        .map_err(|_| RejectReason::bad_request("Invalid group ID"))?;
    GroupMembershipRow::remove_member(&pool, GroupId(group_id), auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes<S>(store: MemoryStore) -> Router<S>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let layer = SessionManagerLayer::new(store)
        .with_secure(false)
        .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));
    Router::new()
        .route("/auth/me", get(self_handler::<S>)
            .put(self_update_handler::<S>))
        .route("/auth/me/groups", get(self_groups_handler::<S>))
        .route("/auth/me/permissions", get(self_permissions_handler::<S>))
        .route("/auth/me/deactivate", post(self_deactivate_handler::<S>))
        .route("/auth/me/leave", post(self_leave_group_handler::<S>))
        .layer(layer)
}
