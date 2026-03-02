use std::fmt;
use std::str;

use serde::{Deserialize, Serialize};
use subseq_util::impl_typed_uuid_path_extractor;
use subseq_util::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct UserId(pub Uuid);

impl TypeTag for UserId {
    fn tag() -> &'static str {
        "user"
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        UserId(uuid)
    }
}

impl_typed_uuid_path_extractor!(UserId);

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl str::FromStr for UserId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(UserId)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use subseq_util::prelude::{FromTypedUuid, TypedUuid};
    use uuid::Uuid;

    use super::UserId;

    fn fixture_uuid() -> Uuid {
        Uuid::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("fixture uuid should parse")
    }

    #[test]
    fn typed_uuid_uses_user_prefix() {
        let uuid = fixture_uuid();
        let typed = TypedUuid::<UserId>::new(uuid);

        assert_eq!(typed.to_string(), format!("user_{}", uuid.simple()));
    }

    #[test]
    fn typed_uuid_accepts_typed_and_untyped_inputs() {
        let uuid = fixture_uuid();
        let typed_input = format!("user_{}", uuid.simple());
        let untyped_input = uuid.to_string();

        let parsed_typed =
            TypedUuid::<UserId>::from_str(&typed_input).expect("typed user id should deserialize");
        let parsed_untyped = TypedUuid::<UserId>::from_str(&untyped_input)
            .expect("untyped user id should deserialize");

        assert_eq!(parsed_typed.uuid, uuid);
        assert_eq!(parsed_untyped.uuid, uuid);
    }

    #[test]
    fn from_typed_uuid_preserves_underlying_uuid() {
        let uuid = fixture_uuid();

        let user_id = UserId::from_typed_uuid(TypedUuid::<UserId>::new(uuid));

        assert_eq!(user_id, UserId(uuid));
    }
}
