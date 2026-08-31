use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ndabi_isa::{
    capability_digest, verify_operands, verify_program, Field, OperandBuilder, ParameterDescriptor,
    ParameterValue, ProgramBuilder, Relation, ScalarType, Schema, SortDirection, SortTerm,
    VerifyLimits,
};
use ndabi_postgres::isa::{FieldBinding, PostgresCatalogue, RelationBinding};
use ndabi_postgres_v1::{
    digest_label, memory_replay_store, OperationBinding, ReviewBatchGraphProfile, ReviewBatchItem,
    ReviewOperandBundleProfile, ServerSession, WireClientSession,
};
use ndabi_protocol::{
    Authority, AuthorityContext, BackendIdentity, ClientSession as DynamicClientSession, Clock,
    DynamicProgramStore, MemoryReplayStore, OperandBundleStore, ProtocolError,
    ServerSession as DynamicServerSession,
};
use ndabi_supabase_v1::{
    JwtVerifier, UserDynamicPostgresBackend, UserReviewBatchGraphBackend,
    UserReviewOperandBundleBackend,
};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::SecretKey;
use postgres::{Client, NoTls};
use rand_core::OsRng;
use serde_json::json;

const REVIEW_BATCH_SQL: &str = "WITH inputs AS (SELECT start_id,item_count,minimum_score,ordinality::bigint AS ordinal FROM unnest($1::bigint[],$2::bigint[],$3::integer[]) WITH ORDINALITY AS input(start_id,item_count,minimum_score,ordinality)) SELECT ordinal,selected.row_count,selected.score_sum FROM inputs CROSS JOIN LATERAL (SELECT COUNT(*)::bigint AS row_count,COALESCE(SUM(score),0)::bigint AS score_sum FROM (SELECT score FROM supabase_items WHERE id >= inputs.start_id AND id < inputs.start_id + inputs.item_count AND score >= inputs.minimum_score ORDER BY id LIMIT inputs.item_count) AS bounded) AS selected ORDER BY ordinal";
const KEY_ID: &str = "supabase-graph-test-key";
const ISSUER: &str = "https://project.test/auth/v1";
const AUDIENCE: &str = "authenticated";

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(self.0)
    }
}

#[test]
#[ignore = "requires NDABI_SUPABASE_GRAPH_TEST_URL"]
fn one_registered_graph_preserves_supabase_rls_and_exact_receipts() {
    let database_url = std::env::var("NDABI_SUPABASE_GRAPH_TEST_URL").expect("Supabase test URL");
    prepare_fixture(&database_url);
    let (verifier, token) = test_identity();
    let user = verifier.admit(&token).expect("admitted user");

    let profile = ReviewBatchGraphProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(149, 151).expect("binding"),
    )
    .expect("profile");
    let registry = profile
        .graph_registry(
            digest_label(b"schema", b"supabase-items-v1"),
            digest_label(
                b"policy",
                b"forced-rls:owner_sub=request.jwt.claims.sub;authenticated;read-only",
            ),
        )
        .expect("registry");
    let context = AuthorityContext::new(
        user.tenant_id(),
        user.principal_id(),
        157,
        digest_label(b"capability", b"supabase-review-batch-read-v1"),
        registry.identity(),
    )
    .expect("context");
    let deadline = user.session_expires_unix_us();
    let authority = Authority::new_read([19; 32], 163, 167, deadline, context).expect("authority");
    let items = [
        ReviewBatchItem::new(10, 100, 50).expect("first item"),
        ReviewBatchItem::new(200, 50, 225).expect("second item"),
        ReviewBatchItem::new(500, 25, 900).expect("third item"),
        ReviewBatchItem::new(1_000, 10, 0).expect("fourth item"),
    ];
    let parameters = profile.parameters(&items).expect("parameters");
    let result_budget = ReviewBatchGraphProfile::maximum_result_bytes(4).expect("result budget");
    let mut wire_client = WireClientSession::new(authority.clone());
    let frame = wire_client
        .encode_graph(
            profile.operation().expect("operation"),
            &parameters,
            result_budget,
            4,
            deadline,
        )
        .expect("frame");
    let postgres = Client::connect(&database_url, NoTls).expect("graph connection");
    let mut backend =
        UserReviewBatchGraphBackend::new_registered(postgres, profile, &registry, &user, 5_000)
            .expect("user graph backend");

    let mismatched_context = AuthorityContext::new(
        user.tenant_id(),
        [99; 16],
        157,
        digest_label(b"capability", b"supabase-review-batch-read-v1"),
        registry.identity(),
    )
    .expect("mismatched context");
    let mismatched_authority =
        Authority::new_read([23; 32], 173, 179, deadline, mismatched_context)
            .expect("mismatched authority");
    let mut mismatched_client = WireClientSession::new(mismatched_authority.clone());
    let mismatched_frame = mismatched_client
        .encode_graph(
            profile.operation().expect("operation"),
            &parameters,
            result_budget,
            4,
            deadline,
        )
        .expect("mismatched frame");
    let mismatched_server =
        ServerSession::new(mismatched_authority, result_budget, 4).expect("mismatched server");
    assert_eq!(
        mismatched_server
            .execute_graph(
                &mismatched_frame,
                &mut backend,
                &mut memory_replay_store(),
                &FixedClock(unix_us()),
            )
            .expect_err("principal mismatch"),
        ProtocolError::AuthorityMismatch,
    );
    assert_eq!(backend.data_queries(), 0);

    let excessive_deadline = deadline.checked_add(1_000_000).expect("excessive deadline");
    let excessive_authority = Authority::new_read([29; 32], 181, 191, excessive_deadline, context)
        .expect("excessive authority");
    let mut excessive_client = WireClientSession::new(excessive_authority.clone());
    let excessive_frame = excessive_client
        .encode_graph(
            profile.operation().expect("operation"),
            &parameters,
            result_budget,
            4,
            excessive_deadline,
        )
        .expect("excessive frame");
    let excessive_server =
        ServerSession::new(excessive_authority, result_budget, 4).expect("excessive server");
    assert_eq!(
        excessive_server
            .execute_graph(
                &excessive_frame,
                &mut backend,
                &mut memory_replay_store(),
                &FixedClock(unix_us()),
            )
            .expect_err("session deadline"),
        ProtocolError::Expired,
    );
    assert_eq!(backend.data_queries(), 0);

    let server = ServerSession::new(authority, result_budget, 4).expect("server");
    let mut replay = memory_replay_store();
    let now = unix_us();
    let execution = server
        .execute_graph(&frame, &mut backend, &mut replay, &FixedClock(now))
        .expect("graph execution");

    assert_eq!(backend.data_queries(), 1);
    assert_eq!(execution.rows, 4);
    assert_eq!(
        decode_result(&execution.bytes),
        [(1, 30, 2_370), (2, 12, 2_844), (3, 0, 0), (4, 5, 5_020),]
    );
    wire_client
        .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
        .expect("receipt");
    assert!(server
        .execute_graph(&frame, &mut backend, &mut replay, &FixedClock(now))
        .is_err());
    assert_eq!(backend.data_queries(), 1);

    let bundle_profile = ReviewOperandBundleProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(197, 199).expect("bundle binding"),
    )
    .expect("bundle profile");
    let bundle_registry = bundle_profile
        .graph_registry(
            digest_label(b"schema", b"supabase-items-v1"),
            digest_label(
                b"policy",
                b"forced-rls:owner_sub=request.jwt.claims.sub;authenticated;read-only",
            ),
        )
        .expect("bundle registry");
    let bundle_context = AuthorityContext::new(
        user.tenant_id(),
        user.principal_id(),
        211,
        digest_label(b"capability", b"supabase-review-operand-bundle-v1"),
        bundle_registry.identity(),
    )
    .expect("bundle context");
    let bundle_authority = Authority::new_read([31; 32], 223, 227, deadline, bundle_context)
        .expect("bundle authority");
    let layout = bundle_profile.operand_layout().expect("bundle layout");
    let (bundle, thresholds) = bundle_profile.operands(&items).expect("bundle operands");
    let mut bundle_client = WireClientSession::new(bundle_authority.clone());
    let registration = bundle_client
        .encode_operand_bundle_registration(
            bundle_profile.operation().expect("bundle operation"),
            &layout,
            229,
            deadline,
            &bundle.operand_values(),
        )
        .expect("bundle registration");
    let bundle_postgres = Client::connect(&database_url, NoTls).expect("bundle connection");
    let mut bundle_backend = UserReviewOperandBundleBackend::new_registered(
        bundle_postgres,
        bundle_profile,
        &bundle_registry,
        &user,
        5_000,
    )
    .expect("user bundle backend");
    let bundle_result_budget =
        ReviewOperandBundleProfile::maximum_result_bytes(4).expect("bundle result budget");
    let bundle_server = ServerSession::new(bundle_authority.clone(), bundle_result_budget, 4)
        .expect("bundle server");
    let mut bundle_store =
        OperandBundleStore::new(&bundle_authority, 4, 65_536, 32_768).expect("bundle store");
    let mut bundle_replay = memory_replay_store();
    let accepted = bundle_server
        .register_operand_bundle(
            &registration,
            &bundle_registry,
            &layout,
            &mut bundle_store,
            &mut bundle_replay,
            &FixedClock(now),
        )
        .expect("accepted bundle");
    let bundle_frame = bundle_client
        .encode_bundled_graph(
            bundle_profile.operation().expect("bundle operation"),
            &layout,
            accepted.bundle_handle,
            &thresholds.operand_values(),
            bundle_result_budget,
            4,
            deadline,
        )
        .expect("bundle frame");
    let bundle_execution = bundle_server
        .execute_bundled_graph(
            &bundle_frame,
            &bundle_registry,
            &layout,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &FixedClock(now),
        )
        .expect("bundle execution");
    assert_eq!(bundle_execution.bytes, execution.bytes);
    assert_eq!(
        decode_result(&bundle_execution.bytes),
        [(1, 30, 2_370), (2, 12, 2_844), (3, 0, 0), (4, 5, 5_020),]
    );
    bundle_client
        .verify_bundled_execution_receipt(
            &bundle_frame,
            accepted.bundle_digest,
            layout.digest(),
            bundle_execution.rows,
            &bundle_execution.bytes,
            &bundle_execution.receipt,
        )
        .expect("bundle receipt");
    assert_eq!(bundle_backend.data_queries(), 1);
    assert_eq!(bundle_backend.bundle_decodes(), 1);
}

#[test]
#[ignore = "requires NDABI_SUPABASE_GRAPH_TEST_URL"]
fn one_dynamic_program_preserves_supabase_rls_and_exact_receipts() {
    const READ: u64 = 1;

    let database_url = std::env::var("NDABI_SUPABASE_GRAPH_TEST_URL").expect("Supabase test URL");
    prepare_fixture(&database_url);
    let (verifier, token) = test_identity();
    let user = verifier.admit(&token).expect("admitted user");
    let schema = Schema::new(vec![Relation::new(
        11,
        READ,
        vec![
            Field::new(101, ScalarType::I64, false, READ).expect("id field"),
            Field::new(102, ScalarType::I64, false, READ).expect("score field"),
            Field::new(103, ScalarType::Utf8, false, READ).expect("owner field"),
        ],
    )
    .expect("relation")])
    .expect("schema");
    let catalogue = PostgresCatalogue::new(
        &schema,
        vec![RelationBinding::new(
            11,
            "public",
            "supabase_items",
            vec![
                FieldBinding::new(101, "id").expect("id binding"),
                FieldBinding::new(102, "score").expect("score binding"),
                FieldBinding::new(103, "owner_sub").expect("owner binding"),
            ],
        )
        .expect("relation binding")],
    )
    .expect("catalogue");
    let mut builder = ProgramBuilder::new(schema.digest(), 16).expect("builder");
    let limit = builder
        .parameter(ParameterDescriptor::new(ScalarType::U64, 8).expect("limit type"))
        .expect("limit parameter");
    let scan = builder.scan(11).expect("scan");
    let projected = builder.project(scan, &[101, 103]).expect("project");
    let sorted = builder
        .sort(
            projected,
            &[SortTerm {
                field: 101,
                direction: SortDirection::Ascending,
            }],
        )
        .expect("sort");
    let limited = builder.limit(sorted, limit).expect("limit");
    builder.return_result(limited).expect("return");
    let program_bytes = builder.finish().expect("program");
    let verified = verify_program(&program_bytes, &schema, READ, VerifyLimits::default())
        .expect("verified program");
    let mut operand_builder = OperandBuilder::new(&verified);
    operand_builder
        .push(ParameterValue::U64(4))
        .expect("limit operand");
    let operand_bytes = operand_builder.finish().expect("operands");
    let operands = verify_operands(&operand_bytes, &verified).expect("verified operands");
    let identity = BackendIdentity::new(
        41,
        43,
        schema.digest(),
        digest_label(
            b"policy",
            b"forced-rls:owner_sub=request.jwt.claims.sub;authenticated;read-only",
        ),
        digest_label(b"profile", b"dynamic-supabase-v1"),
    )
    .expect("identity");
    let context = AuthorityContext::new(
        user.tenant_id(),
        user.principal_id(),
        47,
        capability_digest(READ),
        identity,
    )
    .expect("context");
    let deadline = user.session_expires_unix_us();
    let authority = Authority::new_read([53; 32], 59, 61, deadline, context).expect("authority");
    let postgres = Client::connect(&database_url, NoTls).expect("dynamic connection");
    let mut backend =
        UserDynamicPostgresBackend::new(postgres, identity, schema, catalogue, READ, &user)
            .expect("dynamic backend");
    let server = DynamicServerSession::new(authority.clone(), 4_096, 8).expect("server");
    let mut client = DynamicClientSession::new(authority.clone());
    let mut replay = MemoryReplayStore::default();
    let mut store = DynamicProgramStore::new(16, 4_096, 65_536).expect("program store");
    let registration = client
        .encode_dynamic_program_registration(&verified, deadline)
        .expect("registration");
    let accepted = server
        .register_dynamic_program(
            &registration,
            &mut store,
            &backend,
            &mut replay,
            &FixedClock(unix_us()),
        )
        .expect("accepted program");
    let handle = client
        .verify_dynamic_program_accepted(&registration, &accepted)
        .expect("verified handle");
    let frame = client
        .encode_cached_dynamic(handle, &operands, 4_096, 8, deadline)
        .expect("cached frame");
    let execution = server
        .execute_cached_dynamic(
            &frame,
            &mut store,
            &mut backend,
            &mut replay,
            &FixedClock(unix_us()),
        )
        .expect("dynamic execution");

    assert_eq!(
        decode_dynamic_users(&execution.bytes),
        [(2, "user-a"), (4, "user-a"), (6, "user-a"), (8, "user-a")]
    );
    assert_eq!(execution.rows, 4);
    assert_eq!(backend.prepared_programs(), 1);
    client
        .verify_cached_dynamic_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
        .expect("execution receipt");
}

fn prepare_fixture(database_url: &str) {
    let mut admin = Client::connect(database_url, NoTls).expect("admin connection");
    admin
        .batch_execute(
            "DROP TABLE IF EXISTS supabase_items;
             DO $block$
             BEGIN
                 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN
                     CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
                 END IF;
             END
             $block$;
             CREATE TABLE supabase_items(
                 id bigint PRIMARY KEY,
                 score integer NOT NULL,
                 owner_sub text NOT NULL
             );
             INSERT INTO supabase_items
             SELECT id,id::integer % 10000,
                    CASE WHEN id % 2=0 THEN 'user-a' ELSE 'user-b' END
             FROM generate_series(1,10000) AS id;
             ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY;
             ALTER TABLE supabase_items FORCE ROW LEVEL SECURITY;
             CREATE POLICY owner_reads ON supabase_items FOR SELECT TO authenticated
             USING (owner_sub=current_setting('request.jwt.claims',true)::jsonb->>'sub');
             GRANT USAGE ON SCHEMA public TO authenticated;
             GRANT SELECT ON supabase_items TO authenticated;",
        )
        .expect("Supabase RLS fixture");
}

fn test_identity() -> (JwtVerifier, String) {
    let secret = SecretKey::random(&mut OsRng);
    let private = secret.to_pkcs8_der().expect("private key");
    let public = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("public key");
    let verifier =
        JwtVerifier::new_es256(public.as_bytes(), KEY_ID, ISSUER, AUDIENCE, 300).expect("verifier");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());
    header.kid = Some(KEY_ID.to_string());
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-a",
        "role": "authenticated",
        "exp": now + 300,
    });
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_der(private.as_bytes()),
    )
    .expect("token");
    (verifier, token)
}

fn decode_result(bytes: &[u8]) -> Vec<(u32, u32, i64)> {
    assert_eq!(
        u32::from_le_bytes(bytes[2..6].try_into().expect("count")),
        4
    );
    bytes[6..]
        .chunks_exact(16)
        .map(|item| {
            (
                u32::from_le_bytes(item[0..4].try_into().expect("ordinal")),
                u32::from_le_bytes(item[4..8].try_into().expect("rows")),
                i64::from_le_bytes(item[8..16].try_into().expect("sum")),
            )
        })
        .collect()
}

fn decode_dynamic_users(bytes: &[u8]) -> Vec<(i64, &str)> {
    assert_eq!(&bytes[0..4], b"NDIR");
    assert_eq!(
        u16::from_le_bytes(bytes[16..18].try_into().expect("columns")),
        2
    );
    let rows = u32::from_le_bytes(bytes[12..16].try_into().expect("rows")) as usize;
    let mut offset = 64 + 16;
    (0..rows)
        .map(|_| {
            assert_eq!(bytes[offset], 0b11);
            offset += 1;
            let id = i64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("id"));
            offset += 8;
            let length =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("owner length"))
                    as usize;
            offset += 4;
            let owner = std::str::from_utf8(&bytes[offset..offset + length]).expect("owner");
            offset += length;
            (id, owner)
        })
        .collect()
}

fn unix_us() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_micros(),
    )
    .expect("microseconds")
}
