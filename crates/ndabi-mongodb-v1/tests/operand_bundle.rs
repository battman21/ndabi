use mongodb::bson::{doc, spec::BinarySubtype, Binary, Document};
use mongodb::sync::Client;
use ndabi_mongodb_v1::{
    IdSetBundle, IdSetBundleBackend, IdSetBundleProfile, OperationBinding, ScoreThreshold,
    ROW_BYTES,
};
use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, ClientSession, Clock, OperandBundleStore,
    ProtocolError, ServerSession, SingleSessionReplayStore,
};

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        Ok(NOW)
    }
}

#[test]
#[ignore = "requires NDABI_MONGODB_BUNDLE_TEST_URI"]
fn one_registered_bundle_executes_twice_with_one_static_decode() {
    let uri = std::env::var("NDABI_MONGODB_BUNDLE_TEST_URI").expect("MongoDB test URI");
    let client = Client::with_uri_str(&uri).expect("MongoDB client");
    let database = "ndabi_operand_bundle_test";
    client
        .database(database)
        .drop()
        .run()
        .expect("clean database");
    let documents = (0_i64..256)
        .map(|id| {
            doc! {
                "_id": id,
                "bucket": i32::try_from(id % 8).expect("bucket"),
                "owner": i32::try_from(id % 3).expect("owner"),
                "score": i32::try_from(id).expect("score"),
                "payload": Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![u8::try_from(id % 251).expect("payload"); 64],
                },
            }
        })
        .collect::<Vec<Document>>();
    client
        .database(database)
        .collection::<Document>("items")
        .insert_many(documents)
        .run()
        .expect("MongoDB fixture");

    let profile = IdSetBundleProfile::new(
        database,
        "items",
        OperationBinding::new(71, 73).expect("binding"),
    )
    .expect("profile");
    let registry = profile
        .graph_registry(
            digest_label(b"schema", b"mongodb-items-v1"),
            digest_label(b"policy", b"read-only-v1"),
        )
        .expect("registry");
    let context = AuthorityContext::new(
        [1; 16],
        [2; 16],
        3,
        digest_label(b"capability", b"mongodb-id-set-bundle-v1"),
        registry.identity(),
    )
    .expect("context");
    let authority = Authority::new_read([4; 32], 5, 7, DEADLINE, context).expect("authority");
    let identifiers = [10, 20, 30, 40, 50, 60, 70, 80];
    let bundle = IdSetBundle::new(&identifiers).expect("bundle");
    let layout = profile.operand_layout().expect("layout");
    let mut wire = ClientSession::new(authority.clone());
    let registration = wire
        .encode_operand_bundle_registration(
            profile.operation().expect("operation"),
            &layout,
            11,
            DEADLINE,
            &bundle.operand_values(),
        )
        .expect("registration");
    let server = ServerSession::new(
        authority.clone(),
        ROW_BYTES as u32 * identifiers.len() as u32,
        identifiers.len() as u32,
    )
    .expect("server");
    let mut store = OperandBundleStore::new(&authority, 1, 65_536, 32_768).expect("store");
    let mut replay = SingleSessionReplayStore::default();
    let accepted = server
        .register_operand_bundle(
            &registration,
            &registry,
            &layout,
            &mut store,
            &mut replay,
            &FixedClock,
        )
        .expect("accepted bundle");
    let mut backend =
        IdSetBundleBackend::from_client_registered(client.clone(), profile.clone(), &registry)
            .expect("backend");

    for (threshold, expected_ids) in [(45, vec![50, 60, 70, 80]), (65, vec![70, 80])] {
        let threshold = ScoreThreshold::new(threshold).expect("threshold");
        let frame = wire
            .encode_bundled_graph(
                profile.operation().expect("operation"),
                &layout,
                accepted.bundle_handle,
                &threshold.operand_values(),
                ROW_BYTES as u32 * identifiers.len() as u32,
                identifiers.len() as u32,
                DEADLINE,
            )
            .expect("execution frame");
        let execution = server
            .execute_bundled_graph(
                &frame,
                &registry,
                &layout,
                &mut store,
                &mut backend,
                &mut replay,
                &FixedClock,
            )
            .expect("execution");
        wire.verify_bundled_execution_receipt(
            &frame,
            accepted.bundle_digest,
            layout.digest(),
            execution.rows,
            &execution.bytes,
            &execution.receipt,
        )
        .expect("receipt");
        let ids = execution
            .bytes
            .chunks_exact(ROW_BYTES)
            .map(|row| i64::from_le_bytes(row[0..8].try_into().expect("identifier")))
            .collect::<Vec<_>>();
        assert_eq!(ids, expected_ids);
    }

    assert_eq!(backend.bundle_decodes(), 1);
    assert_eq!(backend.data_queries(), 2);
    client
        .database(database)
        .drop()
        .run()
        .expect("drop database");
}
