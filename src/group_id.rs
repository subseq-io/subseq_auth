use std::fmt;
use std::str;

use serde::{Deserialize, Serialize};
use subseq_util::impl_typed_uuid_path_extractor;
use subseq_util::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct GroupId(pub Uuid);

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TypeTag for GroupId {
    fn tag() -> &'static str {
        "group"
    }
}

impl From<Uuid> for GroupId {
    fn from(uuid: Uuid) -> Self {
        GroupId(uuid)
    }
}

impl_typed_uuid_path_extractor!(GroupId);

impl str::FromStr for GroupId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(GroupId)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use subseq_util::prelude::{FromTypedUuid, TypedUuid};
    use uuid::Uuid;

    use super::GroupId;

    fn fixture_uuid() -> Uuid {
        Uuid::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("fixture uuid should parse")
    }

    #[test]
    fn typed_uuid_uses_group_prefix() {
        let uuid = fixture_uuid();
        let typed = TypedUuid::<GroupId>::new(uuid);

        assert_eq!(typed.to_string(), format!("group_{}", uuid.simple()));
    }

    #[test]
    fn typed_uuid_accepts_typed_and_untyped_inputs() {
        let uuid = fixture_uuid();
        let typed_input = format!("group_{}", uuid.simple());
        let untyped_input = uuid.to_string();

        let parsed_typed = TypedUuid::<GroupId>::from_str(&typed_input)
            .expect("typed group id should deserialize");
        let parsed_untyped = TypedUuid::<GroupId>::from_str(&untyped_input)
            .expect("untyped group id should deserialize");

        assert_eq!(parsed_typed.uuid, uuid);
        assert_eq!(parsed_untyped.uuid, uuid);
    }

    #[test]
    fn from_typed_uuid_preserves_underlying_uuid() {
        let uuid = fixture_uuid();

        let group_id = GroupId::from_typed_uuid(TypedUuid::<GroupId>::new(uuid));

        assert_eq!(group_id, GroupId(uuid));
    }
}
