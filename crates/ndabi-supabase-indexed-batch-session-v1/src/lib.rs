//! Execute one indexed Supabase identifier batch through one admitted PostgreSQL session.
//!
//! The session applies the role, claims, read-only state, and maximum timeout once.
//! Do not return this connection to a generic pool or share it between user identities.
//! Use direct PostgreSQL or Supavisor session mode because transaction mode can change connections.

use ndabi_postgres_v1::RangeProfile;
#[cfg(feature = "benchmark-governed-native")]
use ndabi_protocol::{
    BackendComponentProfile, ComponentTiming, GovernedBatchBackend, ProfiledBatchBackend,
    ProfiledStridedBatchBackend,
};
use ndabi_protocol::{
    BackendIdentity, BatchBackend, BatchItem, BatchItems, BatchOperation, BoundedOutput,
    ExecutionLimits, ProtocolError, StridedBatchBackend, StridedBatchItems,
};
use ndabi_supabase_v1::AdmittedIdentity;
use postgres::{Client, Row, Statement};

const ROWS_PER_ITEM: u32 = 8;
const ENCODED_ROW_BYTES: u64 = 84;
const ITEM_HEADER_BYTES: u64 = 12;

#[derive(Clone, Copy)]
enum OutputEncoding {
    IncrementalWrites,
    ExactBuffer,
}

pub struct IndexedBatchSessionBackend {
    client: Client,
    data_statement: Statement,
    operation: BatchOperation,
    identity: BackendIdentity,
    starts: Vec<i64>,
    identifiers: Vec<i64>,
    data_queries: u64,
    database_result_rows: u64,
    output_encoding: OutputEncoding,
}

impl IndexedBatchSessionBackend {
    pub fn new(
        client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
        maximum_statement_ms: u32,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_output(
            client,
            profile,
            schema_digest,
            policy_digest,
            user,
            maximum_statement_ms,
            OutputEncoding::IncrementalWrites,
        )
    }

    /// Use one exact output buffer for a complete fixed-shape result.
    pub fn new_exact(
        client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
        maximum_statement_ms: u32,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_output(
            client,
            profile,
            schema_digest,
            policy_digest,
            user,
            maximum_statement_ms,
            OutputEncoding::ExactBuffer,
        )
    }

    fn new_with_output(
        mut client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
        maximum_statement_ms: u32,
        output_encoding: OutputEncoding,
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
        let operation = profile.batch_operation()?;
        let identity = profile.identity(schema_digest, policy_digest)?;
        Ok(Self {
            client,
            data_statement,
            operation,
            identity,
            starts: Vec::with_capacity(4_096),
            identifiers: Vec::with_capacity(32_768),
            data_queries: 0,
            database_result_rows: 0,
            output_encoding,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    pub fn database_result_rows(&self) -> u64 {
        self.database_result_rows
    }

    fn execute_items<I>(
        &mut self,
        operation: BatchOperation,
        items: I,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>
    where
        I: ExactSizeIterator<Item = BatchItem>,
    {
        let prepared = self.prepare_items(operation, items, limits)?;
        let rows = self.query_rows(prepared.total_rows)?;
        self.encode_result(operation, prepared, &rows, output)
    }

    fn prepare_items<I>(
        &mut self,
        operation: BatchOperation,
        items: I,
        limits: ExecutionLimits,
    ) -> Result<PreparedBatch, ProtocolError>
    where
        I: ExactSizeIterator<Item = BatchItem>,
    {
        if operation != self.operation {
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
        self.starts.clear();
        self.identifiers.clear();
        let mut previous_end = None;
        for item in items {
            previous_end = Some(append_identifiers(
                item,
                previous_end,
                &mut self.starts,
                &mut self.identifiers,
            )?);
        }
        Ok(PreparedBatch {
            item_count,
            total_rows,
            required_bytes,
        })
    }

    fn query_rows(&mut self, total_rows: u32) -> Result<Vec<Row>, ProtocolError> {
        let rows = self
            .client
            .query(&self.data_statement, &[&self.identifiers])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        self.database_result_rows = self.database_result_rows.saturating_add(rows.len() as u64);
        if rows.len() != total_rows as usize {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(rows)
    }

    fn encode_result(
        &self,
        operation: BatchOperation,
        prepared: PreparedBatch,
        rows: &[Row],
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        match self.output_encoding {
            OutputEncoding::IncrementalWrites => {
                output.reserve_total(prepared.required_bytes)?;
                encode_rows_incrementally(
                    operation,
                    prepared.item_count,
                    &self.starts,
                    rows,
                    output,
                )?;
                output.complete_rows(prepared.total_rows)?;
            }
            OutputEncoding::ExactBuffer => {
                output.write_exact(prepared.required_bytes, prepared.total_rows, |bytes| {
                    encode_rows_exact(operation, prepared.item_count, &self.starts, rows, bytes)
                })?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PreparedBatch {
    item_count: u32,
    total_rows: u32,
    required_bytes: usize,
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
        self.execute_items(operation, items, limits, output)
    }
}

impl StridedBatchBackend for IndexedBatchSessionBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_strided_batch(
        &mut self,
        operation: BatchOperation,
        items: StridedBatchItems,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.execute_items(operation, items, limits, output)
    }
}

#[cfg(feature = "benchmark-governed-native")]
impl GovernedBatchBackend for IndexedBatchSessionBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_governed_batch(
        &mut self,
        operation: BatchOperation,
        items: &[BatchItem],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.execute_items(operation, items.iter().copied(), limits, output)
    }
}

#[cfg(feature = "benchmark-governed-native")]
impl ProfiledBatchBackend for IndexedBatchSessionBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_profiled_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<BackendComponentProfile, ProtocolError> {
        let dispatch_started = ProfileStamp::now()?;
        let prepared = self.prepare_items(operation, items, limits)?;
        let registered_plan_dispatch = dispatch_started.finish()?;
        let database_started = ProfileStamp::now()?;
        let rows = self.query_rows(prepared.total_rows)?;
        let database_execution = database_started.finish()?;
        let encoding_started = ProfileStamp::now()?;
        self.encode_result(operation, prepared, &rows, output)?;
        let result_encoding = encoding_started.finish()?;
        Ok(BackendComponentProfile {
            registered_plan_dispatch,
            database_execution,
            result_encoding,
        })
    }
}

#[cfg(feature = "benchmark-governed-native")]
impl ProfiledStridedBatchBackend for IndexedBatchSessionBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_profiled_strided_batch(
        &mut self,
        operation: BatchOperation,
        items: StridedBatchItems,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<BackendComponentProfile, ProtocolError> {
        let dispatch_started = ProfileStamp::now()?;
        let prepared = self.prepare_items(operation, items, limits)?;
        let registered_plan_dispatch = dispatch_started.finish()?;
        let database_started = ProfileStamp::now()?;
        let rows = self.query_rows(prepared.total_rows)?;
        let database_execution = database_started.finish()?;
        let encoding_started = ProfileStamp::now()?;
        self.encode_result(operation, prepared, &rows, output)?;
        let result_encoding = encoding_started.finish()?;
        Ok(BackendComponentProfile {
            registered_plan_dispatch,
            database_execution,
            result_encoding,
        })
    }
}

#[cfg(feature = "benchmark-governed-native")]
#[derive(Clone, Copy)]
struct ProfileStamp {
    wall_ns: u64,
    cpu_ns: u64,
}

#[cfg(feature = "benchmark-governed-native")]
impl ProfileStamp {
    fn now() -> Result<Self, ProtocolError> {
        Ok(Self {
            wall_ns: profile_clock_ns(libc::CLOCK_MONOTONIC)?,
            cpu_ns: profile_clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)?,
        })
    }

    fn finish(self) -> Result<ComponentTiming, ProtocolError> {
        let end = Self::now()?;
        Ok(ComponentTiming {
            wall_ns: end
                .wall_ns
                .checked_sub(self.wall_ns)
                .ok_or(ProtocolError::ClockFailed)?,
            cpu_ns: end
                .cpu_ns
                .checked_sub(self.cpu_ns)
                .ok_or(ProtocolError::ClockFailed)?,
        })
    }
}

#[cfg(feature = "benchmark-governed-native")]
fn profile_clock_ns(clock: libc::clockid_t) -> Result<u64, ProtocolError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid for one writable timespec.
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(ProtocolError::ClockFailed);
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| ProtocolError::ClockFailed)?;
    let nanoseconds = u64::try_from(value.tv_nsec).map_err(|_| ProtocolError::ClockFailed)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or(ProtocolError::ClockFailed)
}

fn encode_rows_incrementally(
    operation: BatchOperation,
    item_count: u32,
    starts: &[i64],
    rows: &[Row],
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    let mut batch_header = [0_u8; 6];
    batch_header[..2].copy_from_slice(&operation.opcode.to_be_bytes());
    batch_header[2..].copy_from_slice(&item_count.to_be_bytes());
    output.write(&batch_header)?;
    let mut row_index = 0_usize;
    for start in starts {
        let mut item_header = [0_u8; ITEM_HEADER_BYTES as usize];
        item_header[..8].copy_from_slice(&start.to_be_bytes());
        item_header[8..].copy_from_slice(&ROWS_PER_ITEM.to_be_bytes());
        output.write(&item_header)?;
        for expected_id in *start..*start + i64::from(ROWS_PER_ITEM) {
            let mut encoded = [0_u8; ENCODED_ROW_BYTES as usize];
            encode_row(&rows[row_index], expected_id, &mut encoded)?;
            output.write(&encoded)?;
            row_index += 1;
        }
    }
    if row_index != rows.len() {
        return Err(ProtocolError::BackendRefused);
    }
    Ok(())
}

fn encode_rows_exact(
    operation: BatchOperation,
    item_count: u32,
    starts: &[i64],
    rows: &[Row],
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    output[..2].copy_from_slice(&operation.opcode.to_be_bytes());
    output[2..6].copy_from_slice(&item_count.to_be_bytes());
    let mut offset = 6_usize;
    let mut row_index = 0_usize;
    for start in starts {
        let item_end = offset
            .checked_add(ITEM_HEADER_BYTES as usize)
            .ok_or(ProtocolError::OutputShape)?;
        let item = output
            .get_mut(offset..item_end)
            .ok_or(ProtocolError::OutputShape)?;
        item[..8].copy_from_slice(&start.to_be_bytes());
        item[8..].copy_from_slice(&ROWS_PER_ITEM.to_be_bytes());
        offset = item_end;
        for expected_id in *start..*start + i64::from(ROWS_PER_ITEM) {
            let row_end = offset
                .checked_add(ENCODED_ROW_BYTES as usize)
                .ok_or(ProtocolError::OutputShape)?;
            let target = output
                .get_mut(offset..row_end)
                .ok_or(ProtocolError::OutputShape)?;
            encode_row(&rows[row_index], expected_id, target)?;
            row_index += 1;
            offset = row_end;
        }
    }
    if row_index != rows.len() || offset != output.len() {
        return Err(ProtocolError::OutputShape);
    }
    Ok(())
}

fn append_identifiers(
    item: BatchItem,
    previous_end: Option<i64>,
    starts: &mut Vec<i64>,
    identifiers: &mut Vec<i64>,
) -> Result<i64, ProtocolError> {
    if item.first <= 0 || item.second != 0 || item.third != ROWS_PER_ITEM {
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

fn encode_row(row: &Row, expected_id: i64, output: &mut [u8]) -> Result<(), ProtocolError> {
    let id: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
    let bucket: i32 = row.try_get(1).map_err(|_| ProtocolError::BackendRefused)?;
    let owner: i32 = row.try_get(2).map_err(|_| ProtocolError::BackendRefused)?;
    let score: i32 = row.try_get(3).map_err(|_| ProtocolError::BackendRefused)?;
    let payload: &[u8] = row.try_get(4).map_err(|_| ProtocolError::BackendRefused)?;
    if id != expected_id || payload.len() != 64 {
        return Err(ProtocolError::BackendRefused);
    }
    if output.len() != ENCODED_ROW_BYTES as usize {
        return Err(ProtocolError::OutputShape);
    }
    output[..8].copy_from_slice(&id.to_be_bytes());
    output[8..12].copy_from_slice(&bucket.to_be_bytes());
    output[12..16].copy_from_slice(&owner.to_be_bytes());
    output[16..20].copy_from_slice(&score.to_be_bytes());
    output[20..].copy_from_slice(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_identifiers_are_exact_and_ordered() {
        let mut starts = Vec::new();
        let mut identifiers = Vec::new();
        let end = append_identifiers(
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
                append_identifiers(item, previous_end, &mut Vec::new(), &mut Vec::new(),),
                Err(ProtocolError::BackendRefused)
            );
        }
    }
}
