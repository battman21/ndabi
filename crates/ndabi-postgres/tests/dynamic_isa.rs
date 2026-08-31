use ndabi_isa::{
    capability_digest, verify_operands, verify_program, Comparison, Field, OperandBuilder,
    ParameterDescriptor, ParameterValue, ProgramBuilder, Relation, ScalarType, Schema,
    SortDirection, SortTerm, VerifyLimits,
};
use ndabi_postgres::isa::{
    DynamicPostgresBackend, FieldBinding, PostgresCatalogue, RelationBinding,
};
use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, BackendIdentity, ClientSession, Clock,
    DynamicProgramStore, MemoryReplayStore, ProtocolError, ServerSession,
};
use postgres::{Client, NoTls};

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const READ: u64 = 1;

struct TestClock;

impl Clock for TestClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(NOW)
    }
}

fn schema() -> Schema {
    Schema::new(vec![Relation::new(
        11,
        READ,
        vec![
            Field::new(101, ScalarType::I64, false, READ).expect("id field"),
            Field::new(102, ScalarType::Utf8, false, READ).expect("name field"),
            Field::new(103, ScalarType::I64, false, READ).expect("score field"),
        ],
    )
    .expect("relation")])
    .expect("schema")
}

fn catalogue(schema: &Schema) -> PostgresCatalogue {
    PostgresCatalogue::new(
        schema,
        vec![RelationBinding::new(
            11,
            "pg_temp",
            "dynamic_items",
            vec![
                FieldBinding::new(101, "id").expect("id binding"),
                FieldBinding::new(102, "name").expect("name binding"),
                FieldBinding::new(103, "score").expect("score binding"),
            ],
        )
        .expect("relation binding")],
    )
    .expect("catalogue")
}

fn program(schema: &Schema) -> Vec<u8> {
    let mut builder = ProgramBuilder::new(schema.digest(), 16).expect("builder");
    let minimum = builder
        .parameter(ParameterDescriptor::new(ScalarType::I64, 8).expect("minimum type"))
        .expect("minimum parameter");
    let limit = builder
        .parameter(ParameterDescriptor::new(ScalarType::U64, 8).expect("limit type"))
        .expect("limit parameter");
    let scan = builder.scan(11).expect("scan");
    let filtered = builder
        .filter(scan, 103, Comparison::GreaterOrEqual, minimum)
        .expect("filter");
    let projected = builder.project(filtered, &[101, 102]).expect("project");
    let sorted = builder
        .sort(
            projected,
            &[SortTerm {
                field: 101,
                direction: SortDirection::Descending,
            }],
        )
        .expect("sort");
    let limited = builder.limit(sorted, limit).expect("limit");
    builder.return_result(limited).expect("return");
    builder.finish().expect("program")
}

fn authority(schema: &Schema, capability_digest: [u8; 32]) -> Authority {
    let identity = BackendIdentity::new(
        41,
        43,
        schema.digest(),
        digest_label(b"policy", b"dynamic-test"),
        digest_label(b"profile", b"dynamic-postgres-v1"),
    )
    .expect("identity");
    let context =
        AuthorityContext::new([1; 16], [2; 16], 3, capability_digest, identity).expect("context");
    Authority::new_read([4; 32], 5, 6, DEADLINE, context).expect("authority")
}

fn native_result(rows: &[postgres::Row], program_digest: [u8; 32]) -> Vec<u8> {
    let mut output = vec![0_u8; 64];
    output[0..4].copy_from_slice(b"NDIR");
    output[4] = 1;
    output[12..16].copy_from_slice(&(rows.len() as u32).to_le_bytes());
    output[16..18].copy_from_slice(&2_u16.to_le_bytes());
    output[32..64].copy_from_slice(&program_digest);
    output.extend_from_slice(&101_u32.to_le_bytes());
    output.push(ScalarType::I64 as u8);
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&102_u32.to_le_bytes());
    output.push(ScalarType::Utf8 as u8);
    output.extend_from_slice(&[0; 3]);
    for row in rows {
        output.push(0b11);
        let id: i64 = row.get(0);
        let name: String = row.get(1);
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&(name.len() as u32).to_le_bytes());
        output.extend_from_slice(name.as_bytes());
    }
    let length = output.len() as u32;
    output[8..12].copy_from_slice(&length.to_le_bytes());
    output
}

#[test]
#[ignore = "requires NDABI_DYNAMIC_POSTGRES_TEST_URL"]
fn an_unregistered_dynamic_program_matches_native_postgresql() {
    let url = std::env::var("NDABI_DYNAMIC_POSTGRES_TEST_URL").expect("test URL");
    let mut client = Client::connect(&url, NoTls).expect("connect");
    client
        .batch_execute(
            "CREATE TEMP TABLE dynamic_items(id bigint PRIMARY KEY,name text NOT NULL,score bigint NOT NULL);\
             INSERT INTO dynamic_items VALUES (1,'one',10),(2,'two',20),(3,'three',30),(4,'four',40)",
        )
        .expect("fixture");
    let native_rows = client
        .query(
            "SELECT id,name FROM dynamic_items WHERE score >= $1 ORDER BY id DESC LIMIT $2",
            &[&20_i64, &2_i64],
        )
        .expect("native query");

    let schema = schema();
    let program_bytes = program(&schema);
    let verified = verify_program(&program_bytes, &schema, READ, VerifyLimits::default())
        .expect("verified program");
    let mut operand_builder = OperandBuilder::new(&verified);
    operand_builder
        .push(ParameterValue::I64(20))
        .expect("minimum operand");
    operand_builder
        .push(ParameterValue::U64(2))
        .expect("limit operand");
    let operand_bytes = operand_builder.finish().expect("operand block");
    let operands = verify_operands(&operand_bytes, &verified).expect("verified operands");
    let capability_digest = capability_digest(READ);
    let authority = authority(&schema, capability_digest);
    let identity = authority.context().backend();
    let mut backend = DynamicPostgresBackend::new(
        client,
        identity,
        schema.clone(),
        catalogue(&schema),
        READ,
        [1; 16],
        [2; 16],
    )
    .expect("backend");
    let mut client_session = ClientSession::new(authority.clone());
    let server = ServerSession::new(authority, 4_096, 8).expect("server");
    let mut replay = MemoryReplayStore::default();
    let mut program_store = DynamicProgramStore::new(16, 4_096, 65_536).expect("program store");
    let registration = client_session
        .encode_dynamic_program_registration(&verified, DEADLINE)
        .expect("registration");
    let accepted = server
        .register_dynamic_program(
            &registration,
            &mut program_store,
            &backend,
            &mut replay,
            &TestClock,
        )
        .expect("accepted program");
    let handle = client_session
        .verify_dynamic_program_accepted(&registration, &accepted)
        .expect("verified handle");
    let cached_frame = client_session
        .encode_cached_dynamic(handle, &operands, 4_096, 8, DEADLINE)
        .expect("cached frame");
    let cached = server
        .execute_cached_dynamic(
            &cached_frame,
            &mut program_store,
            &mut backend,
            &mut replay,
            &TestClock,
        )
        .expect("cached execution");
    assert_eq!(cached.bytes, native_result(&native_rows, verified.digest()));
    assert_eq!(cached.rows, native_rows.len() as u32);
    client_session
        .verify_cached_dynamic_receipt(&cached_frame, cached.rows, &cached.bytes, &cached.receipt)
        .expect("cached receipt");

    let frame = client_session
        .encode_dynamic(&verified, &operands, 4_096, 8, DEADLINE)
        .expect("frame");
    assert!(cached_frame.len() < frame.len());
    let execution = server
        .execute_dynamic(&frame, &mut backend, &mut replay, &TestClock)
        .expect("dynamic execution");
    assert_eq!(
        execution.bytes,
        native_result(&native_rows, verified.digest())
    );
    assert_eq!(execution.rows, native_rows.len() as u32);
    client_session
        .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
        .expect("receipt");
    assert_eq!(backend.prepared_programs(), 1);

    let repeated_frame = client_session
        .encode_dynamic(&verified, &operands, 4_096, 8, DEADLINE)
        .expect("repeated frame");
    let repeated = server
        .execute_dynamic(&repeated_frame, &mut backend, &mut replay, &TestClock)
        .expect("repeated execution");
    assert_eq!(repeated.bytes, execution.bytes);
    assert_eq!(backend.prepared_programs(), 1);

    let limited_frame = client_session
        .encode_dynamic(&verified, &operands, 4_096, 1, DEADLINE)
        .expect("limited frame");
    assert!(matches!(
        server.execute_dynamic(&limited_frame, &mut backend, &mut replay, &TestClock),
        Err(ProtocolError::RowBudgetExceeded)
    ));
    assert!(matches!(
        server.execute_dynamic(&limited_frame, &mut backend, &mut replay, &TestClock),
        Err(ProtocolError::RowBudgetExceeded)
    ));
    assert_eq!(backend.prepared_programs(), 1);
}
