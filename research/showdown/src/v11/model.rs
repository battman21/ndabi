use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const MIN_RECORDS: usize = 512;
pub const MAX_RECORDS: usize = 1_000_000;
pub const MIN_RESULT_BYTES: usize = 64;
pub const MAX_RESULT_BYTES: usize = 1_048_576;
pub const RECORD_RESULT_BYTES: usize = 32;
pub const BENCHMARK_NOW: u64 = 1_900_000_000;

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    Point,
    Filter,
    Aggregate,
    Temporal,
}

impl Workload {
    #[cfg(test)]
    pub const ALL: [Self; 4] = [Self::Point, Self::Filter, Self::Aggregate, Self::Temporal];

    pub fn opcode(self) -> u8 {
        match self {
            Self::Point => 1,
            Self::Filter => 2,
            Self::Aggregate => 3,
            Self::Temporal => 4,
        }
    }

    pub fn from_opcode(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Point),
            2 => Ok(Self::Filter),
            3 => Ok(Self::Aggregate),
            4 => Ok(Self::Temporal),
            _ => Err("the query opcode is unsupported".to_string()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Point => "point",
            Self::Filter => "filter",
            Self::Aggregate => "aggregate",
            Self::Temporal => "temporal",
        }
    }
}

impl FromStr for Workload {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "point" => Ok(Self::Point),
            "filter" => Ok(Self::Filter),
            "aggregate" => Ok(Self::Aggregate),
            "temporal" => Ok(Self::Temporal),
            _ => Err(format!("unknown workload: {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Query {
    pub workload: Workload,
    pub result_budget: u32,
    pub arguments: [u64; 5],
}

impl Query {
    pub fn fixture(
        workload: Workload,
        records: usize,
        result_bytes: usize,
    ) -> Result<Self, String> {
        let record_count = u64::try_from(records)
            .map_err(|_| "the fixture record count overflowed".to_string())?;
        let result_budget = u32::try_from(result_bytes)
            .map_err(|_| "the fixture result budget overflowed".to_string())?;
        let limit = (result_bytes / RECORD_RESULT_BYTES).max(1) as u64;
        let arguments = match workload {
            Workload::Point => [record_count / 2 + 1, 0, 0, 0, 0],
            Workload::Filter => [3, u64::from(u16::MAX), 400, BENCHMARK_NOW, limit],
            Workload::Aggregate => [3, BENCHMARK_NOW, 0, 0, 0],
            Workload::Temporal => [record_count / 3 + 1, BENCHMARK_NOW - 25, 0, 0, 0],
        };
        Ok(Self {
            workload,
            result_budget,
            arguments,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreparedCommand {
    pub capability_handle: u64,
    pub capability_generation: u32,
    pub query: Query,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TrustedEnvelope {
    pub principal_digest: [u8; 16],
    pub purpose_digest: [u8; 16],
    pub snapshot: u64,
    pub deadline: u64,
    pub result_budget: u32,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreparedCapability {
    pub handle: u64,
    pub generation: u32,
    pub authority_digest: Digest,
    pub principal_digest: [u8; 16],
    pub purpose_digest: [u8; 16],
    pub snapshot: u64,
    pub expires_at: u64,
    pub max_result_bytes: u32,
    pub allowed_operations: u8,
    pub revoked: bool,
}

impl PreparedCapability {
    pub fn fixture(snapshot: u64, result_budget: u32) -> Self {
        let principal_digest = [0x31; 16];
        let purpose_digest = [0x52; 16];
        let mut authority_material = Vec::with_capacity(48);
        authority_material.extend_from_slice(&principal_digest);
        authority_material.extend_from_slice(&purpose_digest);
        authority_material.extend_from_slice(&snapshot.to_le_bytes());
        authority_material.extend_from_slice(&result_budget.to_le_bytes());
        let authority_digest = *blake3::hash(&authority_material).as_bytes();
        let handle = u64::from_le_bytes(
            authority_digest[..8]
                .try_into()
                .unwrap_or([0; std::mem::size_of::<u64>()]),
        );
        Self {
            handle,
            generation: 1,
            authority_digest,
            principal_digest,
            purpose_digest,
            snapshot,
            expires_at: BENCHMARK_NOW + 3_600,
            max_result_bytes: result_budget,
            allowed_operations: 0b0000_1111,
            revoked: false,
        }
    }

    pub fn envelope(self, nonce: u64) -> TrustedEnvelope {
        TrustedEnvelope {
            principal_digest: self.principal_digest,
            purpose_digest: self.purpose_digest,
            snapshot: self.snapshot,
            deadline: BENCHMARK_NOW + 60,
            result_budget: self.max_result_bytes,
            nonce,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: u32,
    pub tenant: u16,
    pub owner: u16,
    pub score: u16,
    pub valid_from: u64,
    pub valid_to: u64,
}

#[derive(Clone, Debug)]
pub struct Dataset {
    pub records: Vec<Record>,
    pub snapshot: u64,
}

impl Dataset {
    pub fn fixture(record_count: usize) -> Result<Self, String> {
        if !(MIN_RECORDS..=MAX_RECORDS).contains(&record_count) {
            return Err(format!(
                "the record count must be between {MIN_RECORDS} and {MAX_RECORDS}"
            ));
        }
        let mut records = Vec::with_capacity(record_count);
        for index in 0..record_count {
            let id = u32::try_from(index + 1)
                .map_err(|_| "the fixture identifier overflowed".to_string())?;
            let valid_from = BENCHMARK_NOW - 100 - (index % 50) as u64;
            let valid_to = if index % 11 == 0 {
                BENCHMARK_NOW - 10
            } else {
                u64::MAX
            };
            records.push(Record {
                id,
                tenant: u16::try_from(index % 16).unwrap_or(0),
                owner: u16::try_from(index % 64).unwrap_or(0),
                score: u16::try_from((index * 37) % 1_000).unwrap_or(0),
                valid_from,
                valid_to,
            });
        }
        Ok(Self {
            records,
            snapshot: 73,
        })
    }

    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.records.capacity() * std::mem::size_of::<Record>()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SemanticResult {
    pub matched_records: u64,
    pub aggregate: u64,
    pub result_digest: Digest,
    pub payload_bytes: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryReceipt {
    pub snapshot: u64,
    pub nonce: u64,
    pub capability_handle: u64,
    pub result_digest: Digest,
}

#[derive(Debug)]
pub struct ResultBuffer {
    pub semantic: SemanticResult,
    pub payload: Vec<u8>,
}

impl ResultBuffer {
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            semantic: SemanticResult::default(),
            payload: Vec::with_capacity(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Session {
    pub last_nonce: u64,
}
