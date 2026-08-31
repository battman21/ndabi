use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, ReviewBatchGraphBackend,
    ReviewBatchGraphProfile, ReviewBatchItem, ReviewGraphBackend, ReviewGraphProfile,
    ReviewOperandBundleBackend, ReviewOperandBundleProfile, ServerSession, WireClientSession,
};
use ndabi_protocol::{Authority, OperandBundleStore, ProtocolError};
use postgres::{Client, NoTls};

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const REVIEW_SQL: &str = "WITH selected AS MATERIALIZED (SELECT id,bucket,owner,score,payload FROM items WHERE id >= $1 AND id < $1 + $2 AND score >= $3 ORDER BY id LIMIT $2) SELECT id,bucket,owner,score,payload,(SUM(score) OVER ())::bigint FROM selected ORDER BY id";
const REVIEW_BATCH_SQL: &str = "WITH inputs AS (SELECT start_id,item_count,minimum_score,ordinality::bigint AS ordinal FROM unnest($1::bigint[],$2::bigint[],$3::integer[]) WITH ORDINALITY AS input(start_id,item_count,minimum_score,ordinality)) SELECT ordinal,selected.row_count,selected.score_sum FROM inputs CROSS JOIN LATERAL (SELECT COUNT(*)::bigint AS row_count,COALESCE(SUM(score),0)::bigint AS score_sum FROM (SELECT score FROM items WHERE id >= inputs.start_id AND id < inputs.start_id + inputs.item_count AND score >= inputs.minimum_score ORDER BY id LIMIT inputs.item_count) AS bounded) AS selected ORDER BY ordinal";

struct FixedClock;

impl ndabi_protocol::Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(NOW)
    }
}

#[test]
#[ignore = "requires NDABI_POSTGRES_GRAPH_TEST_URL and NDABI_POSTGRES_GRAPH_READER_URL"]
fn one_registered_graph_executes_one_read_only_postgresql_query() {
    let admin_url = std::env::var("NDABI_POSTGRES_GRAPH_TEST_URL").expect("admin test URL");
    let reader_url = std::env::var("NDABI_POSTGRES_GRAPH_READER_URL").expect("reader test URL");
    let mut admin = Client::connect(&admin_url, NoTls).expect("admin connection");
    admin
        .batch_execute(
            "DROP TABLE IF EXISTS items;
             CREATE TABLE items(
                 id bigint PRIMARY KEY,
                 bucket integer NOT NULL,
                 owner integer NOT NULL,
                 score integer NOT NULL,
                 payload bytea NOT NULL
             );
             INSERT INTO items
             SELECT id,id::integer % 1024,id::integer % 4096,id::integer % 10000,
                    decode(repeat('ab',64),'hex')
             FROM generate_series(1,10000) AS id;
             DO $block$
             BEGIN
                 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='ndabi_graph_reader') THEN
                     CREATE ROLE ndabi_graph_reader LOGIN;
                 END IF;
             END
             $block$;
             ALTER ROLE ndabi_graph_reader PASSWORD 'ndabi-graph-test-only';
             ALTER ROLE ndabi_graph_reader SET default_transaction_read_only=on;
             GRANT CONNECT ON DATABASE postgres TO ndabi_graph_reader;
             GRANT USAGE ON SCHEMA public TO ndabi_graph_reader;
             GRANT SELECT ON items TO ndabi_graph_reader;",
        )
        .expect("database fixture");

    let mut refusal = Client::connect(&reader_url, NoTls).expect("reader refusal connection");
    assert!(refusal
        .execute("UPDATE items SET score=0 WHERE id=1", &[])
        .is_err());
    drop(refusal);

    let profile =
        ReviewGraphProfile::new(REVIEW_SQL, OperationBinding::new(71, 73).expect("binding"))
            .expect("profile");
    let registry = profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .expect("registry");
    let context = AuthorityContext::new(
        [1; 16],
        [2; 16],
        79,
        digest_label(b"capability", b"review-v1"),
        registry.identity(),
    )
    .expect("context");
    let authority = Authority::new_read([3; 32], 83, 89, DEADLINE, context).expect("authority");
    let parameters = profile.parameters(10, 100, 50).expect("parameters");
    let mut client = WireClientSession::new(authority.clone());
    let frame = client
        .encode_graph(
            profile.operation().expect("operation"),
            &parameters,
            14 + 100 * 84,
            100,
            DEADLINE,
        )
        .expect("frame");
    let postgres = Client::connect(&reader_url, NoTls).expect("reader connection");
    let mut backend =
        ReviewGraphBackend::new_registered(postgres, profile, &registry, 5_000).expect("backend");
    let server = ServerSession::new(authority, 14 + 100 * 84, 100).expect("server");
    let mut replay = memory_replay_store();
    let execution = server
        .execute_graph(&frame, &mut backend, &mut replay, &FixedClock)
        .expect("graph execution");

    assert_eq!(backend.data_queries(), 1);
    assert_eq!(execution.rows, 60);
    assert_eq!(execution.bytes.len(), 14 + 60 * 84);
    assert_eq!(
        u32::from_le_bytes(execution.bytes[2..6].try_into().expect("rows")),
        60
    );
    assert_eq!(
        i64::from_le_bytes(execution.bytes[6..14].try_into().expect("sum")),
        4_770,
    );
    client
        .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
        .expect("receipt");
    assert!(server
        .execute_graph(&frame, &mut backend, &mut replay, &FixedClock)
        .is_err());
    assert_eq!(backend.data_queries(), 1);

    let mut changed_receipt = execution.receipt;
    changed_receipt[0] ^= 1;
    assert!(client
        .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &changed_receipt,)
        .is_err());

    let batch_profile = ReviewBatchGraphProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(91, 97).expect("batch binding"),
    )
    .expect("batch profile");
    let batch_registry = batch_profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .expect("batch registry");
    let batch_context = AuthorityContext::new(
        [4; 16],
        [5; 16],
        101,
        digest_label(b"capability", b"review-batch-v1"),
        batch_registry.identity(),
    )
    .expect("batch context");
    let batch_authority =
        Authority::new_read([6; 32], 103, 107, DEADLINE, batch_context).expect("batch authority");
    let batch_items = [
        ReviewBatchItem::new(10, 100, 50).expect("first batch item"),
        ReviewBatchItem::new(200, 50, 225).expect("second batch item"),
        ReviewBatchItem::new(500, 25, 900).expect("third batch item"),
        ReviewBatchItem::new(1_000, 10, 0).expect("fourth batch item"),
    ];
    let batch_parameters = batch_profile
        .parameters(&batch_items)
        .expect("batch parameters");
    let batch_result_budget =
        ReviewBatchGraphProfile::maximum_result_bytes(4).expect("batch result budget");
    let mut batch_client = WireClientSession::new(batch_authority.clone());
    let batch_frame = batch_client
        .encode_graph(
            batch_profile.operation().expect("batch operation"),
            &batch_parameters,
            batch_result_budget,
            4,
            DEADLINE,
        )
        .expect("batch frame");
    let batch_postgres = Client::connect(&reader_url, NoTls).expect("batch reader connection");
    let mut batch_backend = ReviewBatchGraphBackend::new_registered(
        batch_postgres,
        batch_profile,
        &batch_registry,
        5_000,
    )
    .expect("batch backend");
    let batch_server =
        ServerSession::new(batch_authority, batch_result_budget, 4).expect("batch server");
    let mut batch_replay = memory_replay_store();
    let batch_execution = batch_server
        .execute_graph(
            &batch_frame,
            &mut batch_backend,
            &mut batch_replay,
            &FixedClock,
        )
        .expect("batch graph execution");
    assert_eq!(batch_backend.data_queries(), 1);
    assert_eq!(batch_execution.rows, 4);
    assert_eq!(batch_execution.bytes.len(), batch_result_budget as usize);
    assert_eq!(
        decode_batch_result(&batch_execution.bytes),
        [(1, 60, 4_770), (2, 25, 5_925), (3, 0, 0), (4, 10, 10_045),]
    );
    batch_client
        .verify_execution_receipt(
            &batch_frame,
            batch_execution.rows,
            &batch_execution.bytes,
            &batch_execution.receipt,
        )
        .expect("batch receipt");
    assert!(batch_server
        .execute_graph(
            &batch_frame,
            &mut batch_backend,
            &mut batch_replay,
            &FixedClock,
        )
        .is_err());
    assert_eq!(batch_backend.data_queries(), 1);

    let bundle_profile = ReviewOperandBundleProfile::new(
        REVIEW_BATCH_SQL,
        OperationBinding::new(109, 113).expect("bundle binding"),
    )
    .expect("bundle profile");
    let bundle_registry = bundle_profile
        .graph_registry(
            digest_label(b"schema", b"items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .expect("bundle registry");
    let bundle_context = AuthorityContext::new(
        [7; 16],
        [8; 16],
        127,
        digest_label(b"capability", b"review-operand-bundle-v1"),
        bundle_registry.identity(),
    )
    .expect("bundle context");
    let bundle_authority =
        Authority::new_read([9; 32], 131, 137, DEADLINE, bundle_context).expect("bundle authority");
    let layout = bundle_profile.operand_layout().expect("bundle layout");
    let (bundle, thresholds) = bundle_profile
        .operands(&batch_items)
        .expect("bundle operands");
    let mut bundle_client = WireClientSession::new(bundle_authority.clone());
    let registration = bundle_client
        .encode_operand_bundle_registration(
            bundle_profile.operation().expect("bundle operation"),
            &layout,
            139,
            DEADLINE,
            &bundle.operand_values(),
        )
        .expect("bundle registration");
    let bundle_postgres = Client::connect(&reader_url, NoTls).expect("bundle reader connection");
    let mut bundle_backend = ReviewOperandBundleBackend::new_registered(
        bundle_postgres,
        bundle_profile,
        &bundle_registry,
        5_000,
    )
    .expect("bundle backend");
    let bundle_server = ServerSession::new(bundle_authority.clone(), batch_result_budget, 4)
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
            &FixedClock,
        )
        .expect("accepted bundle");
    let bundle_frame = bundle_client
        .encode_bundled_graph(
            bundle_profile.operation().expect("bundle operation"),
            &layout,
            accepted.bundle_handle,
            &thresholds.operand_values(),
            batch_result_budget,
            4,
            DEADLINE,
        )
        .expect("bundle execution frame");
    let bundle_execution = bundle_server
        .execute_bundled_graph(
            &bundle_frame,
            &bundle_registry,
            &layout,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &FixedClock,
        )
        .expect("bundle execution");
    assert_eq!(bundle_execution.bytes, batch_execution.bytes);
    assert_eq!(
        decode_batch_result(&bundle_execution.bytes),
        [(1, 60, 4_770), (2, 25, 5_925), (3, 0, 0), (4, 10, 10_045),]
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

    let changed_thresholds = bundle_profile
        .thresholds(&[0, 0, 0, 0])
        .expect("changed thresholds");
    let changed_frame = bundle_client
        .encode_bundled_graph(
            bundle_profile.operation().expect("bundle operation"),
            &layout,
            accepted.bundle_handle,
            &changed_thresholds.operand_values(),
            batch_result_budget,
            4,
            DEADLINE,
        )
        .expect("changed execution frame");
    let changed_execution = bundle_server
        .execute_bundled_graph(
            &changed_frame,
            &bundle_registry,
            &layout,
            &mut bundle_store,
            &mut bundle_backend,
            &mut bundle_replay,
            &FixedClock,
        )
        .expect("changed execution");
    assert_eq!(
        decode_batch_result(&changed_execution.bytes),
        [
            (1, 100, 5_950),
            (2, 50, 11_225),
            (3, 25, 12_800),
            (4, 10, 10_045),
        ]
    );
    assert_eq!(bundle_backend.data_queries(), 2);
    assert_eq!(bundle_backend.bundle_decodes(), 1);

    let removal = bundle_client
        .encode_operand_bundle_removal(
            bundle_profile.operation().expect("bundle operation"),
            accepted.bundle_handle,
            DEADLINE,
        )
        .expect("bundle removal");
    bundle_server
        .remove_operand_bundle(
            &removal,
            &bundle_registry,
            &mut bundle_store,
            &mut bundle_replay,
            &FixedClock,
        )
        .expect("removed bundle");
    assert!(bundle_store.is_empty());
}

fn decode_batch_result(bytes: &[u8]) -> Vec<(u32, u32, i64)> {
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
