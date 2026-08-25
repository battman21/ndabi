use ndabi_postgres::{
    Authority, ClientSession, PostgresBackend, ProfileSql, ReadOperation, ServerSession,
};
use postgres::{Client, NoTls};
use serde::Serialize;

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    trusted_service_binding: bool,
    response_bytes: usize,
    receipt_nonzero: bool,
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
    let mut client = Client::connect(&connection, NoTls).map_err(|error| error.to_string())?;
    client
        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        .map_err(|error| error.to_string())?;
    let sql = ProfileSql {
        range: "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE id = ANY($1) ORDER BY id",
        predicate: "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE bucket=$1 AND score >= $2 ORDER BY id LIMIT $3",
        aggregate: "SELECT bucket,COUNT(*)::bigint,SUM(score)::bigint FROM supabase_items WHERE score >= $1 GROUP BY bucket ORDER BY bucket",
        join: "SELECT i.id,i.owner,o.name,i.score,i.payload FROM supabase_items i JOIN supabase_owners o ON o.id=i.owner WHERE i.owner=$1 ORDER BY i.id LIMIT $2",
    };
    let mut backend = PostgresBackend::new(client, sql).map_err(|error| error.to_string())?;
    let authority =
        Authority::new([50; 32], 1, 50, DEADLINE, 10, 11, 12).map_err(|error| error.to_string())?;
    let mut encoder = ClientSession::new(authority.clone());
    let mut server = ServerSession::new(authority, 1_024).map_err(|error| error.to_string())?;
    let frame = encoder
        .encode(ReadOperation::Range { start: 1, count: 2 }, 1_024, DEADLINE)
        .map_err(|error| error.to_string())?;
    let result = server
        .execute(&frame, NOW, &mut backend)
        .map_err(|error| error.to_string())?;
    let passed = result.bytes.len() == 173 && result.receipt.iter().any(|byte| *byte != 0);
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI Supabase binding v5.0",
            trusted_service_binding: passed,
            response_bytes: result.bytes.len(),
            receipt_nonzero: result.receipt.iter().any(|byte| *byte != 0),
        })
        .map_err(|error| error.to_string())?
    );
    if passed {
        Ok(())
    } else {
        Err("the trusted Supabase binding result is invalid".to_string())
    }
}
