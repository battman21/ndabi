//! Execute one indexed Supabase identifier batch through one admitted PostgreSQL session.
//!
//! The session applies the role, claims, read-only state, and maximum timeout once.
//! Do not return this connection to a generic pool or share it between user identities.
//! Use direct PostgreSQL or Supavisor session mode because transaction mode can change connections.

use ndabi_postgres_v1::RangeProfile;
use ndabi_protocol::{
    BackendIdentity, BatchBackend, BatchItem, BatchItems, BatchOperation, BoundedOutput,
    ExecutionLimits, ProtocolError,
};
use ndabi_supabase_v1::AdmittedIdentity;
use postgres::{Client, Row, Statement};

const ROWS_PER_ITEM: u32 = 8;
const ENCODED_ROW_BYTES: u64 = 84;
const ITEM_HEADER_BYTES: u64 = 12;

pub struct IndexedBatchSessionBackend {
    client: Client,
    data_statement: Statement,
    profile: RangeProfile,
    identity: BackendIdentity,
    starts: Vec<i64>,
    identifiers: Vec<i64>,
    data_queries: u64,
    database_result_rows: u64,
}

impl IndexedBatchSessionBackend {
    pub fn new(
        mut client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
        maximum_statement_ms: u32,
    ) -> Result<Self, ProtocolError> {
        if user.role() != "authenticated" || maximum_statement_ms == 0 {
            return Err(ProtocolError::BackendRefused);
        }
        client
            .batch_execute(
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY; SET ROLE authenticated",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let context_statement = client
            .prepare(
                "SELECT set_config('request.jwt.claims',$1,false),set_config('statement_timeout',$2,false)",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let timeout = format!("{maximum_statement_ms}ms");
        client
            .query_one(&context_statement, &[&user.canonical_claims(), &timeout])
            .map_err(|_| ProtocolError::BackendRefused)?;
        let state = client
            .query_one(
                "SELECT current_user,current_setting('transaction_read_only'),current_setting('request.jwt.claims')",
                &[],
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let current_user: String = state
            .try_get(0)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let read_only: String = state
            .try_get(1)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let claims: String = state
            .try_get(2)
            .map_err(|_| ProtocolError::BackendRefused)?;
        if current_user != "authenticated" || read_only != "on" || claims != user.canonical_claims()
        {
            return Err(ProtocolError::BackendRefused);
        }
        let data_statement = client
            .prepare(profile.sql())
            .map_err(|_| ProtocolError::BackendRefused)?;
        let identity = profile.identity(schema_digest, policy_digest)?;
        Ok(Self {
            client,
            data_statement,
            profile,
            identity,
            starts: Vec::with_capacity(4_096),
            identifiers: Vec::with_capacity(32_768),
            data_queries: 0,
            database_result_rows: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    pub fn database_result_rows(&self) -> u64 {
        self.database_result_rows
    }
}

impl BatchBackend for IndexedBatchSessionBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.profile.batch_operation()? {
            return Err(ProtocolError::BackendRefused);
        }
        let item_count =
            u32::try_from(items.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        let total_rows = item_count
            .checked_mul(ROWS_PER_ITEM)
            .ok_or(ProtocolError::RowBudgetExceeded)?;
        if total_rows > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let item_bytes = ITEM_HEADER_BYTES + u64::from(ROWS_PER_ITEM) * ENCODED_ROW_BYTES;
        let required_bytes = 6_u64
            .checked_add(
                u64::from(item_count)
                    .checked_mul(item_bytes)
                    .ok_or(ProtocolError::ResultBudgetExceeded)?,
            )
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if required_bytes > u64::from(limits.maximum_result_bytes) {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let required_bytes =
            usize::try_from(required_bytes).map_err(|_| ProtocolError::ResultBudgetExceeded)?;
        output.reserve_total(required_bytes)?;

        self.starts.clear();
        self.identifiers.clear();
        let mut previous_end = None;
        for item in items {
            previous_end = Some(append_identifiers(
                self.profile,
                item,
                previous_end,
                &mut self.starts,
                &mut self.identifiers,
            )?);
        }

        let rows = self
            .client
            .query(&self.data_statement, &[&self.identifiers])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        self.database_result_rows = self.database_result_rows.saturating_add(rows.len() as u64);
        if rows.len() != total_rows as usize {
            return Err(ProtocolError::BackendRefused);
        }

        output.write(&operation.opcode.to_be_bytes())?;
        output.write(&item_count.to_be_bytes())?;
        let mut row_index = 0_usize;
        for start in &self.starts {
            output.write(&start.to_be_bytes())?;
            output.write(&ROWS_PER_ITEM.to_be_bytes())?;
            for expected_id in *start..*start + i64::from(ROWS_PER_ITEM) {
                encode_row(&rows[row_index], expected_id, output)?;
                row_index += 1;
            }
        }
        if row_index != rows.len() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(())
    }
}

fn append_identifiers(
    profile: RangeProfile,
    item: BatchItem,
    previous_end: Option<i64>,
    starts: &mut Vec<i64>,
    identifiers: &mut Vec<i64>,
) -> Result<i64, ProtocolError> {
    let expected = profile.operation(item.first, ROWS_PER_ITEM)?;
    if item.second != 0 || item.third != ROWS_PER_ITEM || expected.first != item.first {
        return Err(ProtocolError::BackendRefused);
    }
    let end = item
        .first
        .checked_add(i64::from(ROWS_PER_ITEM))
        .ok_or(ProtocolError::BackendRefused)?;
    if previous_end.is_some_and(|value| value > item.first) {
        return Err(ProtocolError::BackendRefused);
    }
    starts.push(item.first);
    identifiers.extend(item.first..end);
    Ok(end)
}

fn encode_row(
    row: &Row,
    expected_id: i64,
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    let id: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
    let bucket: i32 = row.try_get(1).map_err(|_| ProtocolError::BackendRefused)?;
    let owner: i32 = row.try_get(2).map_err(|_| ProtocolError::BackendRefused)?;
    let score: i32 = row.try_get(3).map_err(|_| ProtocolError::BackendRefused)?;
    let payload: &[u8] = row.try_get(4).map_err(|_| ProtocolError::BackendRefused)?;
    if id != expected_id || payload.len() != 64 {
        return Err(ProtocolError::BackendRefused);
    }
    output.write(&id.to_be_bytes())?;
    output.write(&bucket.to_be_bytes())?;
    output.write(&owner.to_be_bytes())?;
    output.write(&score.to_be_bytes())?;
    output.write(payload)?;
    output.complete_row()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndabi_postgres_v1::OperationBinding;

    fn profile() -> RangeProfile {
        RangeProfile::new(
            "SELECT id FROM test WHERE id = ANY($1) ORDER BY id",
            OperationBinding::new(1, 1).expect("binding"),
        )
        .expect("profile")
    }

    #[test]
    fn indexed_identifiers_are_exact_and_ordered() {
        let mut starts = Vec::new();
        let mut identifiers = Vec::new();
        let end = append_identifiers(
            profile(),
            BatchItem::new(11, 0, ROWS_PER_ITEM),
            None,
            &mut starts,
            &mut identifiers,
        )
        .expect("valid item");

        assert_eq!(end, 19);
        assert_eq!(starts, [11]);
        assert_eq!(identifiers, (11..19).collect::<Vec<_>>());
    }

    #[test]
    fn indexed_identifiers_refuse_overlap_and_shape_changes() {
        let invalid = [
            (BatchItem::new(12, 0, ROWS_PER_ITEM), Some(19)),
            (BatchItem::new(20, 1, ROWS_PER_ITEM), Some(19)),
            (BatchItem::new(20, 0, ROWS_PER_ITEM - 1), Some(19)),
        ];
        for (item, previous_end) in invalid {
            assert_eq!(
                append_identifiers(
                    profile(),
                    item,
                    previous_end,
                    &mut Vec::new(),
                    &mut Vec::new(),
                ),
                Err(ProtocolError::BackendRefused)
            );
        }
    }
}
