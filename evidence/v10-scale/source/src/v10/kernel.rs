use super::model::{
    Dataset, PreparedCapability, PreparedCommand, QueryReceipt, Record, ResultBuffer, Session,
    TrustedEnvelope, Workload, BENCHMARK_NOW, MAX_RESULT_BYTES, RECORD_RESULT_BYTES,
};

pub fn execute(
    dataset: &Dataset,
    capability: &PreparedCapability,
    envelope: TrustedEnvelope,
    command: PreparedCommand,
    session: &mut Session,
    result: &mut ResultBuffer,
) -> Result<QueryReceipt, String> {
    validate(dataset, capability, envelope, command, session)?;
    result.payload.clear();
    let mut matched_records = 0u64;
    let mut aggregate = 0u64;
    match command.query.workload {
        Workload::Point => {
            let identifier = command.query.arguments[0];
            let index = identifier
                .checked_sub(1)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| "the point identifier is invalid".to_string())?;
            let record = dataset
                .records
                .get(index)
                .ok_or_else(|| "the point identifier is absent".to_string())?;
            append_record(result, record, usize::MAX)?;
            matched_records = 1;
            aggregate = u64::from(record.score);
        }
        Workload::Filter => {
            let tenant = checked_u16(command.query.arguments[0], "tenant")?;
            let owner = checked_u16(command.query.arguments[1], "owner")?;
            let minimum_score = checked_u16(command.query.arguments[2], "score")?;
            let as_of = command.query.arguments[3];
            let limit = usize::try_from(command.query.arguments[4])
                .map_err(|_| "the filter limit overflowed".to_string())?;
            if limit == 0 {
                return Err("the filter limit is zero".to_string());
            }
            for record in &dataset.records {
                if record.tenant == tenant
                    && (owner == u16::MAX || record.owner == owner)
                    && record.score >= minimum_score
                    && visible(record, as_of)
                {
                    append_record(result, record, limit)?;
                    matched_records += 1;
                    aggregate = aggregate.saturating_add(u64::from(record.score));
                    if usize::try_from(matched_records).unwrap_or(usize::MAX) == limit {
                        break;
                    }
                }
            }
        }
        Workload::Aggregate => {
            let tenant = checked_u16(command.query.arguments[0], "tenant")?;
            let as_of = command.query.arguments[1];
            for record in &dataset.records {
                if record.tenant == tenant && visible(record, as_of) {
                    matched_records += 1;
                    aggregate = aggregate.saturating_add(u64::from(record.score));
                }
            }
        }
        Workload::Temporal => {
            let identifier = command.query.arguments[0];
            let as_of = command.query.arguments[1];
            let index = identifier
                .checked_sub(1)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| "the temporal identifier is invalid".to_string())?;
            let record = dataset
                .records
                .get(index)
                .ok_or_else(|| "the temporal identifier is absent".to_string())?;
            if visible(record, as_of) {
                append_record(result, record, usize::MAX)?;
                matched_records = 1;
                aggregate = u64::from(record.score);
            }
        }
    }
    let payload_bytes = u32::try_from(result.payload.len())
        .map_err(|_| "the result payload length overflowed".to_string())?;
    if payload_bytes > command.query.result_budget {
        return Err("the complete result exceeds the query budget".to_string());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ndabi-v10-semantic-result\0");
    hasher.update(&[command.query.workload.opcode()]);
    for argument in command.query.arguments {
        hasher.update(&argument.to_le_bytes());
    }
    hasher.update(&matched_records.to_le_bytes());
    hasher.update(&aggregate.to_le_bytes());
    hasher.update(&result.payload);
    let result_digest = *hasher.finalize().as_bytes();
    result.semantic = super::model::SemanticResult {
        matched_records,
        aggregate,
        result_digest,
        payload_bytes,
    };
    session.last_nonce = envelope.nonce;
    Ok(QueryReceipt {
        snapshot: envelope.snapshot,
        nonce: envelope.nonce,
        capability_handle: capability.handle,
        result_digest,
    })
}

fn validate(
    dataset: &Dataset,
    capability: &PreparedCapability,
    envelope: TrustedEnvelope,
    command: PreparedCommand,
    session: &Session,
) -> Result<(), String> {
    if capability.revoked {
        return Err("the capability is revoked".to_string());
    }
    if capability.expires_at < BENCHMARK_NOW || envelope.deadline < BENCHMARK_NOW {
        return Err("the operation authority expired".to_string());
    }
    if command.capability_handle != capability.handle
        || command.capability_generation != capability.generation
    {
        return Err("the command capability binding does not match".to_string());
    }
    if envelope.principal_digest != capability.principal_digest {
        return Err("the principal binding does not match".to_string());
    }
    if envelope.purpose_digest != capability.purpose_digest {
        return Err("the purpose binding does not match".to_string());
    }
    if envelope.snapshot != capability.snapshot || envelope.snapshot != dataset.snapshot {
        return Err("the snapshot binding does not match".to_string());
    }
    if envelope.nonce != session.last_nonce.saturating_add(1) {
        return Err("the operation nonce is replayed or out of order".to_string());
    }
    let operation_mask = 1u8 << (command.query.workload.opcode() - 1);
    if capability.allowed_operations & operation_mask == 0 {
        return Err("the capability does not allow this operation".to_string());
    }
    let requested = usize::try_from(command.query.result_budget)
        .map_err(|_| "the result budget overflowed".to_string())?;
    if requested < super::model::MIN_RESULT_BYTES || requested > MAX_RESULT_BYTES {
        return Err("the query result budget is outside the profile".to_string());
    }
    if command.query.result_budget > capability.max_result_bytes
        || command.query.result_budget > envelope.result_budget
    {
        return Err("the query exceeds its trusted result budget".to_string());
    }
    if command.query.workload == Workload::Filter {
        let limit = usize::try_from(command.query.arguments[4])
            .map_err(|_| "the filter limit overflowed".to_string())?;
        let required = limit
            .checked_mul(RECORD_RESULT_BYTES)
            .ok_or_else(|| "the filter result size overflowed".to_string())?;
        if required > requested {
            return Err("the filter result cannot fit its complete result budget".to_string());
        }
    }
    Ok(())
}

fn visible(record: &Record, as_of: u64) -> bool {
    record.valid_from <= as_of && as_of < record.valid_to
}

fn append_record(result: &mut ResultBuffer, record: &Record, limit: usize) -> Result<(), String> {
    let current_records = result.payload.len() / RECORD_RESULT_BYTES;
    if current_records == limit {
        return Ok(());
    }
    let next_length = result
        .payload
        .len()
        .checked_add(RECORD_RESULT_BYTES)
        .ok_or_else(|| "the result payload length overflowed".to_string())?;
    if next_length > result.payload.capacity() {
        return Err("the complete result exceeds the prepared buffer".to_string());
    }
    result.payload.extend_from_slice(&record.id.to_le_bytes());
    result
        .payload
        .extend_from_slice(&record.tenant.to_le_bytes());
    result
        .payload
        .extend_from_slice(&record.owner.to_le_bytes());
    result
        .payload
        .extend_from_slice(&record.score.to_le_bytes());
    result
        .payload
        .extend_from_slice(&record.valid_from.to_le_bytes());
    result
        .payload
        .extend_from_slice(&record.valid_to.to_le_bytes());
    result.payload.extend_from_slice(&[0; 6]);
    debug_assert_eq!(result.payload.len(), next_length);
    Ok(())
}

fn checked_u16(value: u64, field: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("the {field} argument overflowed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v10::model::{Query, Workload};

    fn fixture(workload: Workload) -> (Dataset, PreparedCapability, PreparedCommand) {
        let dataset = Dataset::fixture(512).expect("dataset");
        let query = Query::fixture(workload, 512, 4_096).expect("query");
        let capability = PreparedCapability::fixture(dataset.snapshot, query.result_budget);
        let command = PreparedCommand {
            capability_handle: capability.handle,
            capability_generation: capability.generation,
            query,
        };
        (dataset, capability, command)
    }

    #[test]
    fn every_workload_is_deterministic() {
        for workload in Workload::ALL {
            let (dataset, capability, command) = fixture(workload);
            let mut first = ResultBuffer::with_capacity(4_096);
            let mut second = ResultBuffer::with_capacity(4_096);
            execute(
                &dataset,
                &capability,
                capability.envelope(1),
                command,
                &mut Session::default(),
                &mut first,
            )
            .expect("first execution");
            execute(
                &dataset,
                &capability,
                capability.envelope(1),
                command,
                &mut Session::default(),
                &mut second,
            )
            .expect("second execution");
            assert_eq!(first.semantic, second.semantic);
            assert_eq!(first.payload, second.payload);
        }
    }

    #[test]
    fn dynamic_authority_changes_refuse_before_session_advance() {
        let (dataset, capability, command) = fixture(Workload::Point);
        let valid = capability.envelope(1);
        let cases = [
            TrustedEnvelope {
                principal_digest: [0; 16],
                ..valid
            },
            TrustedEnvelope {
                purpose_digest: [0; 16],
                ..valid
            },
            TrustedEnvelope {
                snapshot: valid.snapshot + 1,
                ..valid
            },
            TrustedEnvelope {
                deadline: BENCHMARK_NOW - 1,
                ..valid
            },
            TrustedEnvelope {
                result_budget: 1,
                ..valid
            },
            TrustedEnvelope { nonce: 2, ..valid },
        ];
        for envelope in cases {
            let mut session = Session::default();
            let mut result = ResultBuffer::with_capacity(4_096);
            assert!(execute(
                &dataset,
                &capability,
                envelope,
                command,
                &mut session,
                &mut result,
            )
            .is_err());
            assert_eq!(session.last_nonce, 0);
        }
    }

    #[test]
    fn replay_refuses() {
        let (dataset, capability, command) = fixture(Workload::Point);
        let mut session = Session::default();
        let mut result = ResultBuffer::with_capacity(4_096);
        execute(
            &dataset,
            &capability,
            capability.envelope(1),
            command,
            &mut session,
            &mut result,
        )
        .expect("first execution");
        assert!(execute(
            &dataset,
            &capability,
            capability.envelope(1),
            command,
            &mut session,
            &mut result,
        )
        .is_err());
    }
}
