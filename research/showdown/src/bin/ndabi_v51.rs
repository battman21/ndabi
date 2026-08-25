use ndabi_session::{
    AccessClass, Authority, Backend, ClientSession, RawOperation, ServerSession, SessionError,
};
use ndabi_write::{CasOperation, PostgresCasBackend, RESULT_BYTES};
use postgres::{Client, NoTls};
use serde::Serialize;

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const MAXIMUM_RESULT_BYTES: u32 = 64;
const UPDATE_SQL: &str = "UPDATE ndabi_write_records SET version=version+1,value=$3 WHERE id=$1 AND version=$2 RETURNING version,value";

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    safety_checks: String,
    final_version: i64,
    final_value: i64,
    receipt_nonzero: bool,
    passed: bool,
}

struct FailOnce<'a> {
    inner: &'a mut PostgresCasBackend,
    fail: bool,
}

impl Backend for FailOnce<'_> {
    fn access_class(&self) -> AccessClass {
        AccessClass::Write
    }

    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
        if self.fail {
            self.fail = false;
            Err(SessionError::backend_refused())
        } else {
            self.inner.execute(operation)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let connection = std::env::args()
        .nth(1)
        .ok_or_else(|| "a PostgreSQL connection is required".to_string())?;
    let client = Client::connect(&connection, NoTls).map_err(|error| error.to_string())?;
    let mut backend =
        PostgresCasBackend::new(client, UPDATE_SQL).map_err(|error| error.to_string())?;
    let first = CasOperation::new(1, 0, 42).map_err(|error| error.to_string())?;
    let binding = write_authority(510)?;
    let mut encoder = ClientSession::new(binding.clone());
    let mut server =
        ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
    let frame = encoder
        .encode(
            first.into_raw().map_err(|error| error.to_string())?,
            RESULT_BYTES as u32,
            DEADLINE,
        )
        .map_err(|error| error.to_string())?;
    let result = server
        .execute(&frame, NOW, &mut backend)
        .map_err(|error| error.to_string())?;
    let receipt_nonzero = result.receipt.iter().any(|byte| *byte != 0);
    let mut passed = 0u32;
    passed += u32::from(result.bytes.len() == RESULT_BYTES);
    passed += u32::from(server.execute(&frame, NOW, &mut backend).is_err());
    passed += u32::from(backend.current(1).map_err(|error| error.to_string())? == (1, 42));

    let stale = CasOperation::new(1, 0, 99).map_err(|error| error.to_string())?;
    passed += u32::from(
        execute_once(&mut backend, write_authority(511)?, stale, 64, NOW, false)?.is_err(),
    );
    passed += u32::from(backend.current(1).map_err(|error| error.to_string())? == (1, 42));

    let changed = CasOperation::new(1, 1, 77).map_err(|error| error.to_string())?;
    passed += u32::from(
        execute_once(&mut backend, write_authority(512)?, changed, 64, NOW, true)?.is_err(),
    );

    let read = Authority::new([51; 32], 1, 513, DEADLINE, 10, 11, 12)
        .map_err(|error| error.to_string())?;
    let write = write_authority(513)?;
    let mut write_encoder = ClientSession::new(write);
    let cross_frame = write_encoder
        .encode(
            changed.into_raw().map_err(|error| error.to_string())?,
            64,
            DEADLINE,
        )
        .map_err(|error| error.to_string())?;
    let mut read_server = ServerSession::new(read, 64).map_err(|error| error.to_string())?;
    passed += u32::from(
        read_server
            .execute(&cross_frame, NOW, &mut backend)
            .is_err(),
    );

    passed += u32::from(
        execute_once(
            &mut backend,
            write_authority(514)?,
            changed,
            64,
            DEADLINE,
            false,
        )?
        .is_err(),
    );
    passed += u32::from(
        execute_once(&mut backend, write_authority(515)?, changed, 65, NOW, false)?.is_err(),
    );
    let unsupported = RawOperation::new(0x82, 1, 1, 77).map_err(|error| error.to_string())?;
    let unsupported_operation = execute_raw(
        &mut backend,
        write_authority(516)?,
        unsupported,
        64,
        NOW,
        false,
    )?;
    passed += u32::from(unsupported_operation.is_err());

    let retry_binding = write_authority(517)?;
    let mut retry_encoder = ClientSession::new(retry_binding.clone());
    let mut retry_server =
        ServerSession::new(retry_binding, 64).map_err(|error| error.to_string())?;
    let retry_frame = retry_encoder
        .encode(
            changed.into_raw().map_err(|error| error.to_string())?,
            64,
            DEADLINE,
        )
        .map_err(|error| error.to_string())?;
    let mut fail_once = FailOnce {
        inner: &mut backend,
        fail: true,
    };
    passed += u32::from(
        retry_server
            .execute(&retry_frame, NOW, &mut fail_once)
            .is_err(),
    );
    passed += u32::from(
        retry_server
            .execute(&retry_frame, NOW, &mut fail_once)
            .is_ok(),
    );
    let (final_version, final_value) = backend.current(1).map_err(|error| error.to_string())?;
    passed += u32::from((final_version, final_value) == (2, 77));
    let all_passed = passed == 13 && receipt_nonzero;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI PostgreSQL write admission v5.1",
            safety_checks: format!("{passed}/13"),
            final_version,
            final_value,
            receipt_nonzero,
            passed: all_passed,
        })
        .map_err(|error| error.to_string())?
    );
    if all_passed {
        Ok(())
    } else {
        Err("the write-admission gate failed".to_string())
    }
}

fn execute_once(
    backend: &mut PostgresCasBackend,
    authority: Authority,
    operation: CasOperation,
    budget: u32,
    now: u64,
    mutate: bool,
) -> Result<Result<ndabi_session::Execution, SessionError>, String> {
    execute_raw(
        backend,
        authority,
        operation.into_raw().map_err(|error| error.to_string())?,
        budget,
        now,
        mutate,
    )
}

fn execute_raw(
    backend: &mut PostgresCasBackend,
    authority: Authority,
    operation: RawOperation,
    budget: u32,
    now: u64,
    mutate: bool,
) -> Result<Result<ndabi_session::Execution, SessionError>, String> {
    let mut encoder = ClientSession::new(authority.clone());
    let mut server =
        ServerSession::new(authority, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
    let mut frame = encoder
        .encode(operation, budget, DEADLINE)
        .map_err(|error| error.to_string())?;
    if mutate {
        frame[40] ^= 1;
    }
    Ok(server.execute(&frame, now, backend))
}

fn write_authority(session: u32) -> Result<Authority, String> {
    Authority::new_write([51; 32], 1, session, DEADLINE, 10, 11, 12)
        .map_err(|error| error.to_string())
}
