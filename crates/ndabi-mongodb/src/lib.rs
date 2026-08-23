//! Execute finite MongoDB read profiles behind the shared NDABI session.
//!
//! The profiles accept typed operands and cannot represent a MongoDB command or write.

use mongodb::bson::{doc, spec::BinarySubtype, Binary, RawDocumentBuf};
use mongodb::sync::{Client, Collection};
use ndabi_session::{Backend, RawOperation, SessionError};
use serde::{Deserialize, Serialize};

pub const FIND_BY_ID: u8 = 0x21;
pub const FIND_ID_WINDOW: u8 = 0x22;
pub const ROW_BYTES: usize = 84;
pub const MAX_BATCH_ITEMS: usize = 128;
pub const BATCH_DATASET_ROWS: i64 = 1_000_000;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchDecode {
    Typed,
    RawBson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdWindow {
    pub first: i64,
    pub count: usize,
    pub stride: u32,
}

pub struct MongoSequentialBatchBackend {
    collection: Collection<MongoItem>,
}

pub struct MongoBatchBackend {
    typed: Collection<MongoItem>,
    raw: Collection<RawDocumentBuf>,
    decode: BatchDecode,
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

impl MongoSequentialBatchBackend {
    pub fn connect(uri: &str) -> Result<Self, SessionError> {
        let client = connect_client(uri)?;
        Ok(Self {
            collection: client.database("ndabi").collection("items"),
        })
    }

    pub fn find_window(&self, window: IdWindow) -> Result<Vec<u8>, SessionError> {
        let mut output = Vec::with_capacity(window.count * ROW_BYTES);
        for id in window.identifiers()? {
            let item = self
                .collection
                .find_one(doc! { "_id": id })
                .run()
                .map_err(|_| SessionError::profile_refused("the MongoDB query failed"))?
                .ok_or_else(|| SessionError::profile_refused("the MongoDB item is absent"))?;
            encode_item_into(&item, &mut output)?;
        }
        Ok(output)
    }
}

impl Backend for MongoSequentialBatchBackend {
    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
        self.find_window(decode_window(operation)?)
    }
}

impl MongoBatchBackend {
    pub fn connect(uri: &str, decode: BatchDecode) -> Result<Self, SessionError> {
        let client = connect_client(uri)?;
        Ok(Self::from_client(client, decode))
    }

    pub fn from_client(client: Client, decode: BatchDecode) -> Self {
        let database = client.database("ndabi");
        Self {
            typed: database.collection("items"),
            raw: database.collection("items"),
            decode,
        }
    }

    pub fn find_window(&self, window: IdWindow) -> Result<Vec<u8>, SessionError> {
        match self.decode {
            BatchDecode::Typed => self.find_window_typed(window),
            BatchDecode::RawBson => self.find_window_raw(window),
        }
    }

    fn find_window_typed(&self, window: IdWindow) -> Result<Vec<u8>, SessionError> {
        let identifiers = window.identifiers()?;
        let single_batch_limit = -i64::try_from(window.count)
            .map_err(|_| SessionError::profile_refused("the MongoDB batch count is invalid"))?;
        let mut cursor = self
            .typed
            .find(doc! { "_id": { "$in": &identifiers } })
            .sort(doc! { "_id": 1 })
            .batch_size(window.count as u32)
            // A negative limit closes the cursor after one server batch. This prevents a
            // confirmation read from issuing a second network operation.
            .limit(single_batch_limit)
            .run()
            .map_err(|_| SessionError::profile_refused("the MongoDB batch query failed"))?;
        let mut output = Vec::with_capacity(window.count * ROW_BYTES);
        for expected in identifiers {
            let item = cursor
                .next()
                .ok_or_else(|| SessionError::profile_refused("the MongoDB batch is short"))?
                .map_err(|_| SessionError::profile_refused("the MongoDB batch row failed"))?;
            if item.id != expected {
                return Err(SessionError::profile_refused(
                    "the MongoDB batch order is invalid",
                ));
            }
            encode_item_into(&item, &mut output)?;
        }
        if cursor.next().is_some() {
            return Err(SessionError::profile_refused("the MongoDB batch is long"));
        }
        Ok(output)
    }

    fn find_window_raw(&self, window: IdWindow) -> Result<Vec<u8>, SessionError> {
        let identifiers = window.identifiers()?;
        let single_batch_limit = -i64::try_from(window.count)
            .map_err(|_| SessionError::profile_refused("the MongoDB batch count is invalid"))?;
        let mut cursor = self
            .raw
            .find(doc! { "_id": { "$in": &identifiers } })
            .sort(doc! { "_id": 1 })
            .batch_size(window.count as u32)
            // Keep the diagnostic raw path equal to the typed server operation.
            .limit(single_batch_limit)
            .run()
            .map_err(|_| SessionError::profile_refused("the MongoDB raw batch query failed"))?;
        let mut output = Vec::with_capacity(window.count * ROW_BYTES);
        for expected in identifiers {
            let item = cursor
                .next()
                .ok_or_else(|| SessionError::profile_refused("the MongoDB raw batch is short"))?
                .map_err(|_| SessionError::profile_refused("the MongoDB raw batch row failed"))?;
            if item.get_i64("_id").map_err(|_| {
                SessionError::profile_refused("the MongoDB raw identifier is invalid")
            })? != expected
            {
                return Err(SessionError::profile_refused(
                    "the MongoDB raw batch order is invalid",
                ));
            }
            encode_raw_item_into(&item, &mut output)?;
        }
        if cursor.next().is_some() {
            return Err(SessionError::profile_refused(
                "the MongoDB raw batch is long",
            ));
        }
        Ok(output)
    }
}

impl Backend for MongoBatchBackend {
    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
        self.find_window(decode_window(operation)?)
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

pub fn batch_operation(
    first: i64,
    count: usize,
    stride: u32,
) -> Result<RawOperation, SessionError> {
    let count = i64::try_from(count)
        .map_err(|_| SessionError::profile_refused("the MongoDB batch count is invalid"))?;
    let operation = RawOperation::new(FIND_ID_WINDOW, first, count, stride)?;
    decode_window(operation)?;
    Ok(operation)
}

pub fn decode_window(operation: RawOperation) -> Result<IdWindow, SessionError> {
    if operation.opcode != FIND_ID_WINDOW {
        return Err(SessionError::profile_refused(
            "the MongoDB batch operation is unsupported",
        ));
    }
    let count = usize::try_from(operation.second)
        .map_err(|_| SessionError::profile_refused("the MongoDB batch count is invalid"))?;
    let window = IdWindow {
        first: operation.first,
        count,
        stride: operation.third,
    };
    window.identifiers()?;
    Ok(window)
}

impl IdWindow {
    pub fn identifiers(self) -> Result<Vec<i64>, SessionError> {
        if self.first < 0 || self.count == 0 || self.count > MAX_BATCH_ITEMS || self.stride == 0 {
            return Err(SessionError::profile_refused(
                "the MongoDB identifier window is invalid",
            ));
        }
        let mut identifiers = Vec::with_capacity(self.count);
        for offset in 0..self.count {
            let scaled = i64::try_from(offset)
                .ok()
                .and_then(|value| value.checked_mul(i64::from(self.stride)))
                .ok_or_else(|| {
                    SessionError::profile_refused("the MongoDB identifier window overflowed")
                })?;
            let identifier = self.first.checked_add(scaled).ok_or_else(|| {
                SessionError::profile_refused("the MongoDB identifier window overflowed")
            })?;
            if identifier >= BATCH_DATASET_ROWS {
                return Err(SessionError::profile_refused(
                    "the MongoDB identifier window exceeds its profile",
                ));
            }
            identifiers.push(identifier);
        }
        Ok(identifiers)
    }
}

fn encode_item(item: &MongoItem) -> Result<Vec<u8>, SessionError> {
    let mut output = Vec::with_capacity(ROW_BYTES);
    encode_item_into(item, &mut output)?;
    Ok(output)
}

fn encode_item_into(item: &MongoItem, output: &mut Vec<u8>) -> Result<(), SessionError> {
    if item.payload.subtype != BinarySubtype::Generic || item.payload.bytes.len() != 64 {
        return Err(SessionError::profile_refused(
            "the MongoDB payload shape is invalid",
        ));
    }
    output.extend_from_slice(&item.id.to_le_bytes());
    output.extend_from_slice(&item.bucket.to_le_bytes());
    output.extend_from_slice(&item.owner.to_le_bytes());
    output.extend_from_slice(&item.score.to_le_bytes());
    output.extend_from_slice(&item.payload.bytes);
    Ok(())
}

fn encode_raw_item_into(item: &RawDocumentBuf, output: &mut Vec<u8>) -> Result<(), SessionError> {
    let id = item
        .get_i64("_id")
        .map_err(|_| SessionError::profile_refused("the MongoDB raw identifier is invalid"))?;
    let bucket = item
        .get_i32("bucket")
        .map_err(|_| SessionError::profile_refused("the MongoDB raw bucket is invalid"))?;
    let owner = item
        .get_i32("owner")
        .map_err(|_| SessionError::profile_refused("the MongoDB raw owner is invalid"))?;
    let score = item
        .get_i32("score")
        .map_err(|_| SessionError::profile_refused("the MongoDB raw score is invalid"))?;
    let payload = item
        .get_binary("payload")
        .map_err(|_| SessionError::profile_refused("the MongoDB raw payload is invalid"))?;
    if payload.subtype != BinarySubtype::Generic || payload.bytes.len() != 64 {
        return Err(SessionError::profile_refused(
            "the MongoDB raw payload shape is invalid",
        ));
    }
    output.extend_from_slice(&id.to_le_bytes());
    output.extend_from_slice(&bucket.to_le_bytes());
    output.extend_from_slice(&owner.to_le_bytes());
    output.extend_from_slice(&score.to_le_bytes());
    output.extend_from_slice(payload.bytes);
    Ok(())
}

fn connect_client(uri: &str) -> Result<Client, SessionError> {
    Client::with_uri_str(uri)
        .map_err(|_| SessionError::profile_refused("the MongoDB connection failed"))
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

    #[test]
    fn batch_operation_is_dense_and_bounded() {
        let operation = batch_operation(10, 8, 3).expect("operation");
        assert_eq!(
            operation,
            RawOperation::new(FIND_ID_WINDOW, 10, 8, 3).expect("raw")
        );
        assert_eq!(
            decode_window(operation)
                .expect("window")
                .identifiers()
                .expect("identifiers"),
            [10, 13, 16, 19, 22, 25, 28, 31]
        );
        assert!(batch_operation(0, 0, 1).is_err());
        assert!(batch_operation(0, MAX_BATCH_ITEMS + 1, 1).is_err());
        assert!(batch_operation(0, 1, 0).is_err());
        assert!(batch_operation(BATCH_DATASET_ROWS - 1, 2, 1).is_err());
        assert!(batch_operation(i64::MAX, 2, u32::MAX).is_err());
    }

    #[test]
    fn raw_and_typed_rows_are_identical() {
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
        let raw = RawDocumentBuf::try_from(&doc! {
            "_id": item.id,
            "bucket": item.bucket,
            "owner": item.owner,
            "score": item.score,
            "payload": item.payload.clone(),
        })
        .expect("raw");
        let typed = encode_item(&item).expect("typed");
        let mut raw_bytes = Vec::new();
        encode_raw_item_into(&raw, &mut raw_bytes).expect("raw row");
        assert_eq!(raw_bytes, typed);
    }
}
