//! Unauthenticated read-only snapshot endpoint.
//!
//! This serves `GET /readonly/snapshot` on a separate, opt-in HTTP listener
//! (see `build_readonly_server` in `tcp_server.rs`). It deliberately has **no**
//! authentication: access control is expected to be enforced by the surrounding
//! network (e.g. a K8s NetworkPolicy or a reverse proxy). The JSON shape mirrors
//! the GraphQL `snapshot` query, and the Go SDK consumes this endpoint directly.

use actix_web::{web, HttpResponse};
use chrono::TimeZone;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::{
    domain::handler::BackendHandler,
    infra::{
        access_control::{
            AccessControlledBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
        },
        graphql::query::serialize_attribute,
        tcp_server::TcpResult,
    },
};

/// Minimal state for the read-only listener: the backend handler plus the set
/// of attribute names to omit from the snapshot (applied to both user and group
/// attributes). Unlike `AppState`, it carries no JWT keys, mail options or
/// server URL, since this endpoint never authenticates or sends mail.
pub(crate) struct ReadonlyState<Backend> {
    pub backend_handler: AccessControlledBackendHandler<Backend>,
    pub deny_attributes: HashSet<String>,
}

impl<Backend: BackendHandler> ReadonlyState<Backend> {
    fn get_readonly_handler(&self) -> &impl ReadonlyBackendHandler {
        self.backend_handler.unsafe_get_handler()
    }
}

#[derive(Serialize)]
struct SnapshotDto {
    users: Vec<UserDto>,
    groups: Vec<GroupDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDto {
    id: String,
    email: String,
    display_name: String,
    first_name: String,
    last_name: String,
    creation_date: String,
    uuid: String,
    groups: Vec<UserGroupDto>,
    attributes: Vec<AttributeDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserGroupDto {
    display_name: String,
}

#[derive(Serialize)]
struct AttributeDto {
    name: String,
    value: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDto {
    id: i32,
    display_name: String,
    users: Vec<GroupUserDto>,
    attributes: Vec<AttributeDto>,
}

#[derive(Serialize)]
struct GroupUserDto {
    id: String,
}

/// Registers the read-only routes. Mounted by `build_readonly_server` on a
/// listener with no auth middleware.
pub(crate) fn configure_readonly_endpoint<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: BackendHandler + 'static,
{
    cfg.service(
        web::resource("/readonly/snapshot").route(web::get().to(snapshot_handler::<Backend>)),
    );
}

async fn snapshot_handler<Backend>(data: web::Data<ReadonlyState<Backend>>) -> HttpResponse
where
    Backend: BackendHandler + 'static,
{
    match build_snapshot(&data).await {
        Ok(dto) => HttpResponse::Ok().json(dto),
        Err(e) => {
            // Avoid leaking internal error details to unauthenticated callers.
            tracing::error!("read-only snapshot failed: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn build_snapshot<Backend>(data: &ReadonlyState<Backend>) -> TcpResult<SnapshotDto>
where
    Backend: BackendHandler + 'static,
{
    let handler = data.get_readonly_handler();
    let schema = handler.get_schema().await?;
    let user_attributes = &schema.get_schema().user_attributes;
    let group_attributes = &schema.get_schema().group_attributes;
    let users = handler.list_users(None, true).await?;
    let groups = handler.list_groups(None).await?;

    // Invert user->groups into group_id->members so we don't issue a query per
    // group. `list_users(.., get_groups = true)` already carries each user's
    // groups, mirroring what the GraphQL `group.users` resolver returns.
    let mut members: HashMap<i32, Vec<GroupUserDto>> = HashMap::new();

    let mut user_dtos = Vec::with_capacity(users.len());
    for entry in users {
        let user = entry.user;
        let attributes: Vec<AttributeDto> = user
            .attributes
            .iter()
            .filter(|a| !data.deny_attributes.contains(a.name.as_str()))
            .filter_map(|a| {
                user_attributes.get_attribute_schema(&a.name).map(|s| AttributeDto {
                    name: a.name.to_string(),
                    value: serialize_attribute(a, s),
                })
            })
            .collect();
        let scalar = |name: &str| -> String {
            attributes
                .iter()
                .find(|a| a.name == name)
                .and_then(|a| a.value.first().cloned())
                .unwrap_or_default()
        };
        let groups = entry.groups.unwrap_or_default();
        let mut group_dtos = Vec::with_capacity(groups.len());
        for g in groups {
            members
                .entry(g.group_id.0)
                .or_default()
                .push(GroupUserDto { id: user.user_id.as_str().to_string() });
            group_dtos.push(UserGroupDto { display_name: g.display_name.to_string() });
        }
        user_dtos.push(UserDto {
            id: user.user_id.as_str().to_string(),
            email: user.email.as_str().to_string(),
            display_name: user.display_name.clone().unwrap_or_default(),
            first_name: scalar("first_name"),
            last_name: scalar("last_name"),
            creation_date: chrono::Utc.from_utc_datetime(&user.creation_date).to_rfc3339(),
            uuid: user.uuid.as_str().to_string(),
            groups: group_dtos,
            attributes,
        });
    }

    let group_dtos = groups
        .into_iter()
        .map(|g| {
            let attributes: Vec<AttributeDto> = g
                .attributes
                .iter()
                .filter(|a| !data.deny_attributes.contains(a.name.as_str()))
                .filter_map(|a| {
                    group_attributes.get_attribute_schema(&a.name).map(|s| AttributeDto {
                        name: a.name.to_string(),
                        value: serialize_attribute(a, s),
                    })
                })
                .collect();
            GroupDto {
                id: g.id.0,
                display_name: g.display_name.to_string(),
                users: members.remove(&g.id.0).unwrap_or_default(),
                attributes,
            }
        })
        .collect();

    Ok(SnapshotDto { users: user_dtos, groups: group_dtos })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            handler::{AttributeList, AttributeSchema, Schema},
            types::{
                AttributeType, AttributeValue, Group, GroupDetails, GroupId, Serialized, User,
                UserAndGroups, UserId,
            },
        },
        infra::test_utils::MockTestBackendHandler,
    };
    use chrono::TimeZone;

    fn string_attr(name: &str) -> AttributeSchema {
        AttributeSchema {
            name: name.into(),
            attribute_type: AttributeType::String,
            is_list: false,
            is_visible: true,
            is_editable: true,
            is_hardcoded: true,
        }
    }

    fn handler_with_alice() -> AccessControlledBackendHandler<MockTestBackendHandler> {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().returning(|| {
            Ok(Schema {
                user_attributes: AttributeList {
                    attributes: vec![string_attr("first_name")],
                },
                group_attributes: AttributeList {
                    attributes: vec![string_attr("club_name")],
                },
                extra_user_object_classes: Vec::new(),
                extra_group_object_classes: Vec::new(),
            })
        });
        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: User {
                    user_id: UserId::new("alice"),
                    email: "alice@example.com".into(),
                    display_name: Some("Administrator".to_owned()),
                    attributes: vec![AttributeValue {
                        name: "first_name".into(),
                        value: Serialized::from("Alice"),
                    }],
                    ..Default::default()
                },
                groups: Some(vec![GroupDetails {
                    group_id: GroupId(1),
                    display_name: "lldap_admin".into(),
                    creation_date: chrono::Utc.timestamp_nanos(0).naive_utc(),
                    uuid: crate::uuid!("00000000000000000000000000000001"),
                    attributes: Vec::new(),
                }]),
            }])
        });
        mock.expect_list_groups().returning(|_| {
            Ok(vec![Group {
                id: GroupId(1),
                display_name: "lldap_admin".into(),
                creation_date: chrono::Utc.timestamp_nanos(0).naive_utc(),
                uuid: crate::uuid!("00000000000000000000000000000001"),
                users: vec![UserId::new("alice")],
                attributes: vec![AttributeValue {
                    name: "club_name".into(),
                    value: Serialized::from("Gang of Four"),
                }],
            }])
        });
        AccessControlledBackendHandler::new(mock)
    }

    #[tokio::test]
    async fn maps_users_groups_and_membership() {
        let state = ReadonlyState {
            backend_handler: handler_with_alice(),
            deny_attributes: HashSet::new(),
        };
        let snap = build_snapshot(&state).await.unwrap();

        assert_eq!(snap.users.len(), 1);
        let user = &snap.users[0];
        assert_eq!(user.id, "alice");
        assert_eq!(user.first_name, "Alice");
        assert_eq!(user.attributes.len(), 1);
        assert_eq!(user.attributes[0].name, "first_name");
        assert_eq!(user.attributes[0].value, vec!["Alice".to_owned()]);
        assert_eq!(user.groups.len(), 1);
        assert_eq!(user.groups[0].display_name, "lldap_admin");

        // The group's member list is inverted from the user's groups.
        let admin = snap
            .groups
            .iter()
            .find(|g| g.display_name == "lldap_admin")
            .unwrap();
        assert_eq!(admin.id, 1);
        assert_eq!(admin.users.len(), 1);
        assert_eq!(admin.users[0].id, "alice");

        // Group attributes are serialized just like user attributes.
        assert_eq!(admin.attributes.len(), 1);
        assert_eq!(admin.attributes[0].name, "club_name");
        assert_eq!(admin.attributes[0].value, vec!["Gang of Four".to_owned()]);
    }

    #[tokio::test]
    async fn denylist_filters_attribute_and_derived_field() {
        let state = ReadonlyState {
            backend_handler: handler_with_alice(),
            deny_attributes: HashSet::from(["first_name".to_owned(), "club_name".to_owned()]),
        };
        let snap = build_snapshot(&state).await.unwrap();

        let user = &snap.users[0];
        assert!(user.attributes.is_empty());
        // firstName is derived from the (now-filtered) attributes, so it blanks.
        assert_eq!(user.first_name, "");
        // The denylist applies to group attributes too.
        assert!(snap.groups[0].attributes.is_empty());
    }
}
