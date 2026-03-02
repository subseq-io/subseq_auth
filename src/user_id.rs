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
