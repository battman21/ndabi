//! Issue restart-scoped NDABI bindings without a per-request durable write.
//!
//! The authority owner supplies a fresh secret and generation after every restart.
//! An old frame then fails authentication before it can reach replay state.

use std::fmt;

use zeroize::Zeroize;

use crate::column_v03::{ColumnBinding, ColumnError};

const COLUMN_KEY_DOMAIN: &[u8] = b"ndabi-ephemeral-column-key-v1";

pub struct EphemeralEpoch {
    generation: u64,
    root_key: [u8; 32],
}

impl fmt::Debug for EphemeralEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralEpoch")
            .field("generation", &self.generation)
            .field("root_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for EphemeralEpoch {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

impl EphemeralEpoch {
    pub fn new(generation: u64, root_key: [u8; 32]) -> Result<Self, ColumnError> {
        if generation == 0 {
            return Err(ColumnError::GenerationMismatch);
        }
        if root_key == [0; 32] {
            return Err(ColumnError::ZeroBinding);
        }
        Ok(Self {
            generation,
            root_key,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn column_binding(
        &self,
        session_handle: u32,
        capability_handle: u32,
        schema_handle: u32,
        max_result_bytes: u32,
        expires_unix_us: u64,
    ) -> Result<ColumnBinding, ColumnError> {
        let mut hasher = blake3::Hasher::new_keyed(&self.root_key);
        hasher.update(COLUMN_KEY_DOMAIN);
        hasher.update(&self.generation.to_le_bytes());
        hasher.update(&session_handle.to_le_bytes());
        hasher.update(&capability_handle.to_le_bytes());
        hasher.update(&schema_handle.to_le_bytes());
        let key = *hasher.finalize().as_bytes();
        hasher.zeroize();
        ColumnBinding::new(
            session_handle,
            capability_handle,
            schema_handle,
            self.generation,
            max_result_bytes,
            expires_unix_us,
            key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column_v03::{
        ColumnBatchFrame, ColumnVerifier, OPERATION_IDEMPOTENT, OPERATION_READ,
    };

    fn frame(generation: u64) -> ColumnBatchFrame {
        ColumnBatchFrame {
            flags: 0,
            session_handle: 7,
            capability_handle: 11,
            schema_handle: 13,
            generation,
            nonce: 1,
            deadline_unix_us: u64::MAX,
            result_budget: 1_024,
            plan_handle: 17,
            result_shape: 19,
            transaction_group: 0,
            operation_flags: OPERATION_READ | OPERATION_IDEMPOTENT,
            rows: 2,
            columns: 1,
            row_bytes: 8,
            parameters: [23i64.to_le_bytes(), 29i64.to_le_bytes()].concat(),
        }
    }

    #[test]
    fn a_restart_invalidates_every_old_frame_without_disk_state() {
        let first = EphemeralEpoch::new(17, [0x41; 32]).expect("first epoch");
        let first_binding = first
            .column_binding(7, 11, 13, 1_024, u64::MAX)
            .expect("first binding");
        let bytes = frame(first.generation())
            .encode(&first_binding)
            .expect("old frame");
        assert!(ColumnVerifier::new(first_binding, 0).verify(&bytes).is_ok());

        let restarted = EphemeralEpoch::new(18, [0x42; 32]).expect("restarted epoch");
        let restarted_binding = restarted
            .column_binding(7, 11, 13, 1_024, u64::MAX)
            .expect("restarted binding");
        assert!(ColumnVerifier::new(restarted_binding, 0)
            .verify(&bytes)
            .is_err());
    }

    #[test]
    fn epoch_secrets_are_redacted_and_zero_is_refused() {
        let epoch = EphemeralEpoch::new(17, [0x41; 32]).expect("epoch");
        let debug = format!("{epoch:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("65, 65, 65"));
        assert!(EphemeralEpoch::new(17, [0; 32]).is_err());
    }
}
