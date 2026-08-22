//! Execute a finite MongoDB point-read profile behind the shared NDABI session.
//!
//! The profile accepts one identifier and cannot represent a MongoDB command or write.

use mongodb::bson::{doc, spec::BinarySubtype, Binary};
use mongodb::sync::{Client, Collection};
use ndabi_session::{Backend, RawOperation, SessionError};
use serde::{Deserialize, Serialize};

pub const FIND_BY_ID: u8 = 0x21;
pub const ROW_BYTES: usize = 84;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MongoItem {
    #[serde(rename = "_id")]
    pub id: i64,
    pub bucket: i32,
    pub owner: i32,
    pub score: i32,
    pub payload: Binary,
}

pub struct MongoBackend {
    collection: Collection<MongoItem>,
}

impl MongoBackend {
    pub fn connect(uri: &str) -> Result<Self, SessionError> {
        let client = Client::with_uri_str(uri)
            .map_err(|_| SessionError::profile_refused("the MongoDB connection failed"))?;
        Ok(Self {
            collection: client.database("ndabi").collection("items"),
        })
    }

    pub fn find_by_id(&self, id: i64) -> Result<Vec<u8>, SessionError> {
        if !(0..100_000).contains(&id) {
            return Err(SessionError::profile_refused(
                "the MongoDB identifier exceeds its profile",
            ));
        }
        let item = self
            .collection
            .find_one(doc! { "_id": id })
            .run()
            .map_err(|_| SessionError::profile_refused("the MongoDB query failed"))?
            .ok_or_else(|| SessionError::profile_refused("the MongoDB item is absent"))?;
        encode_item(&item)
    }
}

impl Backend for MongoBackend {
    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
        if operation.opcode != FIND_BY_ID || operation.second != 0 || operation.third != 0 {
            return Err(SessionError::profile_refused(
                "the MongoDB operation is unsupported",
            ));
        }
        self.find_by_id(operation.first)
    }
}

pub fn operation(id: i64) -> Result<RawOperation, SessionError> {
    if !(0..100_000).contains(&id) {
        return Err(SessionError::profile_refused(
            "the MongoDB identifier exceeds its profile",
        ));
    }
    RawOperation::new(FIND_BY_ID, id, 0, 0)
}

fn encode_item(item: &MongoItem) -> Result<Vec<u8>, SessionError> {
    if item.payload.subtype != BinarySubtype::Generic || item.payload.bytes.len() != 64 {
        return Err(SessionError::profile_refused(
            "the MongoDB payload shape is invalid",
        ));
    }
    let mut output = Vec::with_capacity(ROW_BYTES);
    output.extend_from_slice(&item.id.to_le_bytes());
    output.extend_from_slice(&item.bucket.to_le_bytes());
    output.extend_from_slice(&item.owner.to_le_bytes());
    output.extend_from_slice(&item.score.to_le_bytes());
    output.extend_from_slice(&item.payload.bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_is_finite_and_bounded() {
        assert_eq!(
            operation(12).expect("operation"),
            RawOperation::new(FIND_BY_ID, 12, 0, 0).expect("raw")
        );
        assert!(operation(-1).is_err());
        assert!(operation(100_000).is_err());
    }

    #[test]
    fn canonical_row_has_the_registered_width() {
        let item = MongoItem {
            id: 1,
            bucket: 2,
            owner: 3,
            score: 4,
            payload: Binary {
                subtype: BinarySubtype::Generic,
                bytes: vec![5; 64],
            },
        };
        assert_eq!(encode_item(&item).expect("row").len(), ROW_BYTES);
    }
}
