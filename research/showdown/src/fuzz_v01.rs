//! Run a deterministic mutation campaign against every current NDABI frame parser.
//!
//! This campaign gives repeatable regression evidence without a corpus or external fuzzer.
//! It does not replace coverage-guided fuzzing or a sustained sanitiser campaign.

use serde::Serialize;

use crate::column_v03::{
    ColumnBatchFrame, ColumnBinding, ColumnVerifier, OPERATION_IDEMPOTENT as COLUMN_IDEMPOTENT,
    OPERATION_READ as COLUMN_READ,
};
use crate::core_v01;
use crate::core_v02;

const KEY: [u8; 32] = [0x46; 32];
const EDGE_LENGTHS: [usize; 18] = [
    0, 1, 15, 16, 47, 48, 79, 80, 81, 95, 96, 97, 127, 128, 129, 1_024, 4_096, 32_768,
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MutationReport {
    pub seed: u64,
    pub cases_per_parser: u64,
    pub parser_count: u64,
    pub malformed_frames_refused: u64,
    pub authenticated_mutations_refused: u64,
    pub state_transition_checks: u64,
}

pub fn run(seed: u64, cases_per_parser: u64) -> Result<MutationReport, String> {
    if cases_per_parser == 0 {
        return Err("cases_per_parser must be greater than zero".into());
    }
    let mut random = SplitMix64::new(seed);
    let core_v01 = core_v01_frame(1)?;
    let core_v02 = core_v02_frame(1)?;
    let column = column_frame(1, u64::MAX)?;
    let mut malformed_frames_refused = 0u64;
    let mut authenticated_mutations_refused = 0u64;

    for _ in 0..cases_per_parser {
        let malformed = random_frame(&mut random);
        refuse(
            core_v01::SessionVerifier::new(core_v01_binding()?, 0)
                .verify_at(&malformed, 0)
                .is_err(),
            "core v1.0 accepted a random frame",
        )?;
        refuse(
            core_v02::SessionVerifier::new(core_v02_binding()?, 0)
                .verify_at(&malformed, 0)
                .is_err(),
            "core v1.1 accepted a random frame",
        )?;
        refuse(
            ColumnVerifier::new(column_binding()?, 0)
                .verify_at(&malformed, 0)
                .is_err(),
            "column v1.2 accepted a random frame",
        )?;
        malformed_frames_refused += 3;

        let changed = mutate(&core_v01, &mut random);
        refuse(
            core_v01::SessionVerifier::new(core_v01_binding()?, 0)
                .verify_at(&changed, 0)
                .is_err(),
            "core v1.0 accepted an authenticated-frame mutation",
        )?;
        let changed = mutate(&core_v02, &mut random);
        refuse(
            core_v02::SessionVerifier::new(core_v02_binding()?, 0)
                .verify_at(&changed, 0)
                .is_err(),
            "core v1.1 accepted an authenticated-frame mutation",
        )?;
        let changed = mutate(&column, &mut random);
        refuse(
            ColumnVerifier::new(column_binding()?, 0)
                .verify_at(&changed, 0)
                .is_err(),
            "column v1.2 accepted an authenticated-frame mutation",
        )?;
        authenticated_mutations_refused += 3;
    }

    exercise_core_v01_states()?;
    exercise_core_v02_states()?;
    exercise_column_states()?;

    Ok(MutationReport {
        seed,
        cases_per_parser,
        parser_count: 3,
        malformed_frames_refused,
        authenticated_mutations_refused,
        state_transition_checks: 15,
    })
}

fn refuse(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn random_frame(random: &mut SplitMix64) -> Vec<u8> {
    let length = if random.next() & 1 == 0 {
        EDGE_LENGTHS[random.index(EDGE_LENGTHS.len())]
    } else {
        random.index(32_769)
    };
    let mut bytes = vec![0u8; length];
    random.fill(&mut bytes);
    bytes
}

fn mutate(bytes: &[u8], random: &mut SplitMix64) -> Vec<u8> {
    match random.next() % 3 {
        0 => {
            let mut changed = bytes.to_vec();
            let index = random.index(changed.len());
            changed[index] ^= 1 << (random.next() % 8);
            changed
        }
        1 => bytes[..random.index(bytes.len())].to_vec(),
        _ => {
            let extension = 1 + random.index(64);
            let mut changed = Vec::with_capacity(bytes.len() + extension);
            changed.extend_from_slice(bytes);
            let start = changed.len();
            changed.resize(start + extension, 0);
            random.fill(&mut changed[start..]);
            changed
        }
    }
}

fn core_v01_binding() -> Result<core_v01::SessionBinding, String> {
    core_v01::SessionBinding::new(7, 11, 13, 17, 65_536, u64::MAX, KEY)
        .map_err(|error| error.to_string())
}

fn core_v02_binding() -> Result<core_v02::SessionBinding, String> {
    core_v02::SessionBinding::new(7, 11, 13, 17, 65_536, u64::MAX, KEY)
        .map_err(|error| error.to_string())
}

fn column_binding() -> Result<ColumnBinding, String> {
    ColumnBinding::new(7, 11, 13, 17, 65_536, u64::MAX, KEY).map_err(|error| error.to_string())
}

fn core_v01_frame(nonce: u64) -> Result<Vec<u8>, String> {
    core_v01::Frame {
        kind: core_v01::FrameKind::ExecuteOne,
        flags: 0,
        session_handle: 7,
        capability_handle: 11,
        schema_handle: 13,
        generation: 17,
        nonce,
        deadline_unix_us: u64::MAX,
        result_budget: 65_536,
        operations: vec![core_v01::Operation {
            id: 1,
            plan_handle: 19,
            transaction_group: 0,
            result_shape: 23,
            flags: core_v01::OPERATION_READ | core_v01::OPERATION_IDEMPOTENT,
            dependencies: Vec::new(),
            parameters: b"mutation-campaign".to_vec(),
        }],
    }
    .encode(&core_v01_binding()?)
    .map_err(|error| error.to_string())
}

fn core_v02_frame(nonce: u64) -> Result<Vec<u8>, String> {
    core_v02::Frame {
        kind: core_v02::FrameKind::ExecuteOne,
        flags: 0,
        session_handle: 7,
        capability_handle: 11,
        schema_handle: 13,
        generation: 17,
        nonce,
        deadline_unix_us: u64::MAX,
        result_budget: 65_536,
        operations: vec![core_v02::Operation {
            id: 1,
            plan_handle: 19,
            transaction_group: 0,
            result_shape: 23,
            flags: core_v02::OPERATION_READ | core_v02::OPERATION_IDEMPOTENT,
            dependencies: Vec::new(),
            parameters: b"mutation-campaign".to_vec(),
        }],
    }
    .encode(&core_v02_binding()?)
    .map_err(|error| error.to_string())
}

fn column_frame(nonce: u64, deadline_unix_us: u64) -> Result<Vec<u8>, String> {
    ColumnBatchFrame {
        flags: 0,
        session_handle: 7,
        capability_handle: 11,
        schema_handle: 13,
        generation: 17,
        nonce,
        deadline_unix_us,
        result_budget: 65_536,
        plan_handle: 19,
        result_shape: 23,
        transaction_group: 0,
        operation_flags: COLUMN_READ | COLUMN_IDEMPOTENT,
        rows: 2,
        columns: 1,
        row_bytes: 8,
        parameters: [29i64.to_le_bytes(), 31i64.to_le_bytes()].concat(),
    }
    .encode(&column_binding()?)
    .map_err(|error| error.to_string())
}

fn exercise_core_v01_states() -> Result<(), String> {
    let first = core_v01_frame(1)?;
    let second = core_v01_frame(2)?;
    let mut changed = second.clone();
    changed[0] ^= 1;
    let mut verifier = core_v01::SessionVerifier::new(core_v01_binding()?, 0);
    refuse(
        verifier.verify_at(&changed, 0).is_err(),
        "core v1.0 accepted mutation",
    )?;
    refuse(
        verifier.last_nonce() == 0,
        "core v1.0 advanced after refusal",
    )?;
    refuse(
        verifier.verify_at(&first, 0).is_ok(),
        "core v1.0 refused valid frame",
    )?;
    refuse(
        verifier.verify_at(&first, 0).is_err(),
        "core v1.0 accepted replay",
    )?;
    refuse(
        verifier.verify_at(&second, 0).is_ok(),
        "core v1.0 refused monotonic nonce",
    )
}

fn exercise_core_v02_states() -> Result<(), String> {
    let first = core_v02_frame(1)?;
    let second = core_v02_frame(2)?;
    let mut changed = second.clone();
    changed[0] ^= 1;
    let mut verifier = core_v02::SessionVerifier::new(core_v02_binding()?, 0);
    refuse(
        verifier.verify_at(&changed, 0).is_err(),
        "core v1.1 accepted mutation",
    )?;
    refuse(
        verifier.last_nonce() == 0,
        "core v1.1 advanced after refusal",
    )?;
    refuse(
        verifier.verify_at(&first, 0).is_ok(),
        "core v1.1 refused valid frame",
    )?;
    refuse(
        verifier.verify_at(&first, 0).is_err(),
        "core v1.1 accepted replay",
    )?;
    refuse(
        verifier.verify_at(&second, 0).is_ok(),
        "core v1.1 refused monotonic nonce",
    )
}

fn exercise_column_states() -> Result<(), String> {
    let expired = column_frame(1, 20)?;
    let current = column_frame(1, 40)?;
    let second = column_frame(2, 40)?;
    let mut verifier = ColumnVerifier::new(column_binding()?, 0);
    refuse(
        verifier.verify_at(&expired, 20).is_err(),
        "column v1.2 accepted expiry",
    )?;
    refuse(
        verifier.last_nonce() == 0,
        "column v1.2 advanced after expiry",
    )?;
    refuse(
        verifier.verify_at(&current, 20).is_ok(),
        "column v1.2 refused valid frame",
    )?;
    refuse(
        verifier.verify_at(&current, 20).is_err(),
        "column v1.2 accepted replay",
    )?;
    refuse(
        verifier.verify_at(&second, 20).is_ok(),
        "column v1.2 refused monotonic nonce",
    )
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        usize::try_from(self.next() % u64::try_from(upper).expect("bounded upper"))
            .expect("bounded index")
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let value = self.next().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_mutation_campaign_covers_every_parser() {
        let report = run(0x4e44_4142_495f_465a, 4_096).expect("mutation campaign");
        assert_eq!(report.parser_count, 3);
        assert_eq!(report.malformed_frames_refused, 12_288);
        assert_eq!(report.authenticated_mutations_refused, 12_288);
        assert_eq!(report.state_transition_checks, 15);
    }
}
