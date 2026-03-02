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
