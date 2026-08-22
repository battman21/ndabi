//! This module tests durable canonical events without claiming production custody.
//!
//! A complete changed record refuses. A torn final append yields the verified complete prefix.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::kernel_v06::{
    verify_and_replay_event, EventReceipt, EventSlot, KernelState, PreparedCapability,
    EVENT_CAPACITY,
};

const MAGIC: &[u8; 4] = b"N7LG";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 7;
const RECEIPT_BYTES: usize = 48;
const HASH_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub struct DurableLog {
    path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub state: KernelState,
    pub complete_events: u64,
    pub torn_tail: bool,
}

impl DurableLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_and_sync(&self, event: &EventSlot) -> Result<(), String> {
        let record = encode_record(event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.write_all(&record).map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())
    }

    pub fn recover(
        &self,
        capability: &PreparedCapability,
        base: &KernelState,
    ) -> Result<Recovery, String> {
        if !self.path.is_file() {
            return Ok(Recovery {
                state: base.clone(),
                complete_events: 0,
                torn_tail: false,
            });
        }
        let bytes = fs::read(&self.path).map_err(|error| error.to_string())?;
        let mut state = base.clone();
        let mut cursor = 0usize;
        let mut complete_events = 0u64;
        while cursor < bytes.len() {
            let remaining = &bytes[cursor..];
            if remaining.len() < HEADER_BYTES {
                return Ok(Recovery {
                    state,
                    complete_events,
                    torn_tail: true,
                });
            }
            if &remaining[..4] != MAGIC || remaining[4] != VERSION {
                return Err("the durable event record header changed".to_string());
            }
            let event_len = usize::from(u16::from_le_bytes([remaining[5], remaining[6]]));
            if event_len == 0 || event_len > EVENT_CAPACITY {
                return Err("the durable event length is invalid".to_string());
            }
            let record_len = HEADER_BYTES + event_len + RECEIPT_BYTES + HASH_BYTES;
            if remaining.len() < record_len {
                return Ok(Recovery {
                    state,
                    complete_events,
                    torn_tail: true,
                });
            }
            let record = &remaining[..record_len];
            let hash_start = record_len - HASH_BYTES;
            let expected = blake3::hash(&record[..hash_start]);
            if expected.as_bytes() != &record[hash_start..] {
                return Err("the durable event record hash changed".to_string());
            }
            let receipt_start = HEADER_BYTES + event_len;
            let receipt = decode_receipt(&record[receipt_start..hash_start])?;
            let mut event = EventSlot {
                receipt,
                ..EventSlot::default()
            };
            event.len = u16::try_from(event_len)
                .map_err(|_| "the durable event length overflowed".to_string())?;
            event.bytes[..event_len].copy_from_slice(&record[HEADER_BYTES..receipt_start]);
            verify_and_replay_event(capability, &event, &mut state)?;
            complete_events = complete_events.saturating_add(1);
            cursor += record_len;
        }
        Ok(Recovery {
            state,
            complete_events,
            torn_tail: false,
        })
    }
}

fn encode_record(event: &EventSlot) -> Result<Vec<u8>, String> {
    let event_len = usize::from(event.len);
    if event_len == 0 || event_len > EVENT_CAPACITY {
        return Err("the durable event length is invalid".to_string());
    }
    let mut record = Vec::with_capacity(HEADER_BYTES + event_len + RECEIPT_BYTES + HASH_BYTES);
    record.extend_from_slice(MAGIC);
    record.push(VERSION);
    record.extend_from_slice(&event.len.to_le_bytes());
    record.extend_from_slice(&event.bytes[..event_len]);
    push_receipt(&mut record, event.receipt);
    let hash = blake3::hash(&record);
    record.extend_from_slice(hash.as_bytes());
    Ok(record)
}

fn push_receipt(output: &mut Vec<u8>, receipt: EventReceipt) {
    output.extend_from_slice(&receipt.revision.to_le_bytes());
    output.extend_from_slice(&receipt.chain_root);
    output.extend_from_slice(&receipt.result_handle.to_le_bytes());
}

fn decode_receipt(bytes: &[u8]) -> Result<EventReceipt, String> {
    if bytes.len() != RECEIPT_BYTES {
        return Err("the durable event receipt length changed".to_string());
    }
    let revision = read_u64(&bytes[..8])?;
    let mut chain_root = [0u8; 32];
    chain_root.copy_from_slice(&bytes[8..40]);
    let result_handle = read_u64(&bytes[40..48])?;
    Ok(EventReceipt {
        revision,
        chain_root,
        result_handle,
    })
}

fn read_u64(bytes: &[u8]) -> Result<u64, String> {
    let fixed: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "the durable integer length changed".to_string())?;
    Ok(u64::from_le_bytes(fixed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_v06::{execute_prepared, fixed_changes, KernelScratch, PreparedCommand};

    fn append_events(
        log: &DurableLog,
        count: u64,
    ) -> Result<(KernelState, PreparedCapability), String> {
        let mut state = KernelState::fixture();
        let capability = PreparedCapability::fixture();
        let mut command = PreparedCommand::fixture(capability, fixed_changes());
        for index in 0..count {
            command.expected_revision = state.revision;
            command.changes[0].status = u8::try_from((index + 1) % 4).unwrap_or(0);
            command.changes[0].priority = u8::try_from((index + 2) % 5).unwrap_or(0);
            let mut scratch = KernelScratch::default();
            execute_prepared(&capability, &command, &mut state, &mut scratch)?;
            log.append_and_sync(&scratch.event)?;
        }
        Ok((state, capability))
    }

    #[test]
    fn a_reopened_log_replays_every_complete_event() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let log = DurableLog::new(directory.path().join("events.ndabi"));
        let base = KernelState::fixture();
        let (expected, capability) = append_events(&log, 32).expect("append events");
        let recovery = log.recover(&capability, &base).expect("recover log");
        assert_eq!(recovery.state, expected);
        assert_eq!(recovery.complete_events, 32);
        assert!(!recovery.torn_tail);
    }

    #[test]
    fn a_torn_final_append_recovers_only_the_complete_prefix() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let log = DurableLog::new(directory.path().join("events.ndabi"));
        let base = KernelState::fixture();
        let (_, capability) = append_events(&log, 3).expect("append events");
        let complete = fs::read(log.path()).expect("read complete log");
        let third_start = record_offsets(&complete).expect("record offsets")[2];
        OpenOptions::new()
            .write(true)
            .open(log.path())
            .expect("open log")
            .set_len(u64::try_from(complete.len() - 9).expect("log length"))
            .expect("truncate log");
        let recovery = log.recover(&capability, &base).expect("recover prefix");
        assert_eq!(recovery.complete_events, 2);
        assert!(recovery.torn_tail);
        assert!(third_start < complete.len());
    }

    #[test]
    fn a_changed_complete_record_refuses() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let log = DurableLog::new(directory.path().join("events.ndabi"));
        let base = KernelState::fixture();
        let (_, capability) = append_events(&log, 1).expect("append event");
        let mut bytes = fs::read(log.path()).expect("read log");
        let final_byte = bytes.len() - 1;
        bytes[final_byte] ^= 1;
        fs::write(log.path(), bytes).expect("change complete record");
        assert!(log.recover(&capability, &base).is_err());
    }

    fn record_offsets(bytes: &[u8]) -> Result<Vec<usize>, String> {
        let mut offsets = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            if bytes.len() - cursor < HEADER_BYTES {
                return Err("the test log header is incomplete".to_string());
            }
            offsets.push(cursor);
            let event_len = usize::from(u16::from_le_bytes([bytes[cursor + 5], bytes[cursor + 6]]));
            cursor += HEADER_BYTES + event_len + RECEIPT_BYTES + HASH_BYTES;
        }
        Ok(offsets)
    }
}
