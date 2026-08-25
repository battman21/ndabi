mod application;
mod database;
mod receipt;
mod sqlite;
mod wire;

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use application::AppEvidence;
use database::DbEvidence;
use measure::ArmMeasurement;
use ndabi_showdown::{alloc::CountingAllocator, measure, white_tree};
use white_tree::WhiteTreeEvidence;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

const LIMITATIONS: [&str; 12] = [
    "This is a local POC benchmark, not a production benchmark.",
    "SQLite is not PostgreSQL, MongoDB, or Supabase.",
    "The White Tree track uses fixture storage, not a signed production database.",
    "NDABI local measures removed serialisation, not network transport.",
    "NDABI wire excludes network, TLS, and remote-provider latency.",
    "Diagnostic phase timings include timer overhead and do not sum exactly to complete latency.",
    "The allocation counter covers Rust allocations, not SQLite internal allocations.",
    "Retained Rust bytes exclude process RSS, linked libraries, and SQLite memory.",
    "Thread CPU uses the local operating-system clock, not hardware performance counters.",
    "The prototype format is not the NDABI RFC.",
    "The separate token canary measures provider reports, not this benchmark process.",
    "The local scheduler is not isolated, so repeated p95 values can vary.",
];

#[derive(Clone, Copy, Debug, Serialize)]
struct Config {
    rows: usize,
    application_tasks: usize,
    iterations: usize,
    warmup: usize,
}

#[derive(Debug, Serialize)]
struct Environment {
    os: String,
    architecture: String,
    rustc: String,
    sqlite: String,
    git_commit: String,
    git_worktree_state: String,
    olx_core_source_sha256: String,
    process_peak_rss_bytes: u64,
}

#[derive(Debug, Serialize)]
struct GateCheck {
    id: &'static str,
    label: &'static str,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct HardGate {
    passed: bool,
    checks: Vec<GateCheck>,
}

#[derive(Debug, Serialize)]
struct RubricCheck {
    id: &'static str,
    label: &'static str,
    target: &'static str,
    observed: String,
    passed: bool,
    weight: u32,
}

#[derive(Debug, Serialize)]
struct Rubric {
    score: u32,
    maximum_score: u32,
    verdict: &'static str,
    comparison: &'static str,
    checks: Vec<RubricCheck>,
}

#[derive(Debug, Serialize)]
struct Attribution {
    request_reduction_percent: f64,
    response_reduction_percent: f64,
    p95_reduction_percent: f64,
    thread_cpu_reduction_percent: f64,
    allocated_bytes_reduction_percent: f64,
}

#[derive(Debug, Serialize)]
struct LocalAttribution {
    p95_reduction_percent: f64,
    thread_cpu_reduction_percent: f64,
    allocated_bytes_reduction_percent: f64,
    allocation_count_reduction_percent: f64,
}

#[derive(Debug, Serialize)]
struct DatabaseReport {
    #[serde(flatten)]
    evidence: DbEvidence,
    hard_gate: HardGate,
    rubric: Rubric,
    human_to_tuned: Attribution,
    tuned_to_wire: Attribution,
    tuned_to_local: LocalAttribution,
}

#[derive(Debug, Serialize)]
struct ApplicationReport {
    #[serde(flatten)]
    evidence: AppEvidence,
    hard_gate: HardGate,
    rubric: Rubric,
    human_to_tuned: Attribution,
    tuned_to_wire: Attribution,
    tuned_to_local: LocalAttribution,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    generated_at_unix_seconds: u64,
    environment: Environment,
    config: Config,
    overall_verdict: &'static str,
    database: DatabaseReport,
    application: ApplicationReport,
    white_tree: WhiteTreeReport,
    limitations: [&'static str; 12],
}

#[derive(Debug, Serialize)]
struct WhiteTreeReport {
    #[serde(flatten)]
    evidence: WhiteTreeEvidence,
    hard_gate: HardGate,
    rubric: Rubric,
    human_to_tuned: Attribution,
    tuned_to_wire: Attribution,
    tuned_to_local: LocalAttribution,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("ndabi-showdown: {error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let config = parse_args(std::env::args().skip(1))?;
    let database_evidence = database::run(config.rows, config.iterations, config.warmup)?;
    let application_evidence = application::run(config.rows, config.iterations, config.warmup)?;
    let white_tree_evidence = white_tree::run(config.iterations, config.warmup)?;

    let database_gate = database_gate(&database_evidence);
    let application_gate = application_gate(&application_evidence);
    let white_tree_gate = white_tree_gate(&white_tree_evidence);
    let database_rubric = score(&database_evidence.arms, database_gate.passed)?;
    let application_rubric = score(&application_evidence.arms, application_gate.passed)?;
    let white_tree_rubric = score_white_tree(&white_tree_evidence.arms, white_tree_gate.passed)?;
    let overall_verdict = overall_verdict(
        database_gate.passed,
        database_rubric.score,
        application_gate.passed,
        application_rubric.score,
        white_tree_gate.passed,
        white_tree_rubric.score,
    );

    let database_human_to_tuned = attribution(&database_evidence.arms, "human", "tuned")?;
    let database_tuned_to_wire = attribution(&database_evidence.arms, "tuned", "wire")?;
    let database_tuned_to_local = local_attribution(&database_evidence.arms)?;
    let application_human_to_tuned = attribution(&application_evidence.arms, "human", "tuned")?;
    let application_tuned_to_wire = attribution(&application_evidence.arms, "tuned", "wire")?;
    let application_tuned_to_local = local_attribution(&application_evidence.arms)?;
    let white_tree_human_to_tuned = attribution(&white_tree_evidence.arms, "human", "tuned")?;
    let white_tree_tuned_to_wire = attribution(&white_tree_evidence.arms, "tuned", "wire")?;
    let white_tree_tuned_to_local = local_attribution(&white_tree_evidence.arms)?;

    let report = Report {
        schema: "ndabi-poc-result-v0.5",
        status: "local-poc-measurement",
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        environment: environment(),
        config,
        overall_verdict,
        database: DatabaseReport {
            evidence: database_evidence,
            hard_gate: database_gate,
            rubric: database_rubric,
            human_to_tuned: database_human_to_tuned,
            tuned_to_wire: database_tuned_to_wire,
            tuned_to_local: database_tuned_to_local,
        },
        application: ApplicationReport {
            evidence: application_evidence,
            hard_gate: application_gate,
            rubric: application_rubric,
            human_to_tuned: application_human_to_tuned,
            tuned_to_wire: application_tuned_to_wire,
            tuned_to_local: application_tuned_to_local,
        },
        white_tree: WhiteTreeReport {
            evidence: white_tree_evidence,
            hard_gate: white_tree_gate,
            rubric: white_tree_rubric,
            human_to_tuned: white_tree_human_to_tuned,
            tuned_to_wire: white_tree_tuned_to_wire,
            tuned_to_local: white_tree_tuned_to_local,
        },
        limitations: LIMITATIONS,
    };

    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

fn white_tree_gate(evidence: &WhiteTreeEvidence) -> HardGate {
    let checks = vec![
        GateCheck {
            id: "semantic-equality",
            label: "All White Tree arms return one canonical context",
            passed: evidence.semantic_results_equal,
        },
        GateCheck {
            id: "receipt-equality",
            label: "All White Tree arms return one canonical receipt",
            passed: evidence.receipts_equal,
        },
        GateCheck {
            id: "trusted-envelope",
            label: "All White Tree arms carry one trusted envelope",
            passed: evidence.trusted_envelopes_equal,
        },
        GateCheck {
            id: "prune-before-open",
            label: "White Tree prunes the unrelated partition before opening",
            passed: evidence.partitions_scanned == 1
                && evidence.partitions_pruned == 1
                && evidence.physical_bytes_read > 0,
        },
        GateCheck {
            id: "negative-cases",
            label: "All White Tree negative cases refuse",
            passed: evidence.refusals_passed == evidence.refusals_total,
        },
        GateCheck {
            id: "policy-before-execution",
            label: "Refused White Tree requests execute no engine query",
            passed: evidence.refused_engine_executions == 0,
        },
        GateCheck {
            id: "deterministic-encoding",
            label: "Repeated White Tree encoding is byte-identical",
            passed: evidence.deterministic_encodings,
        },
    ];
    HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut rows = 4_096usize;
    let mut iterations = 2_000usize;
    let mut warmup = 100usize;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} needs a value"))?;
        match argument.as_str() {
            "--rows" => rows = parse_number(&argument, &value)?,
            "--iterations" => iterations = parse_number(&argument, &value)?,
            "--warmup" => warmup = parse_number(&argument, &value)?,
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !(256..=65_536).contains(&rows) {
        return Err("--rows must be between 256 and 65536".to_string());
    }
    if !(20..=50_000).contains(&iterations) {
        return Err("--iterations must be between 20 and 50000".to_string());
    }
    if !iterations.is_multiple_of(40) {
        return Err("--iterations must be divisible by forty".to_string());
    }
    if warmup > 5_000 {
        return Err("--warmup must not exceed 5000".to_string());
    }
    Ok(Config {
        rows,
        application_tasks: (rows / 8).clamp(128, 1_024),
        iterations,
        warmup,
    })
}

fn parse_number(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("{name} is not a positive integer: {error}"))
}

fn database_gate(evidence: &DbEvidence) -> HardGate {
    let checks = vec![
        GateCheck {
            id: "semantic-equality",
            label: "All database arms return one canonical result",
            passed: evidence.semantic_results_equal,
        },
        GateCheck {
            id: "trusted-envelope",
            label: "All database arms carry one trusted envelope",
            passed: evidence.trusted_envelopes_equal,
        },
        GateCheck {
            id: "receipt-verification",
            label: "Every database receipt verifies its exact result",
            passed: evidence.receipts_verified,
        },
        GateCheck {
            id: "negative-cases",
            label: "All database negative cases refuse",
            passed: evidence.refusals_passed == evidence.refusals_total,
        },
        GateCheck {
            id: "policy-before-execution",
            label: "Refused database requests execute no query",
            passed: evidence.refused_database_executions == 0,
        },
        GateCheck {
            id: "deterministic-encoding",
            label: "Repeated database encoding is byte-identical",
            passed: evidence.deterministic_encodings,
        },
    ];
    HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn application_gate(evidence: &AppEvidence) -> HardGate {
    let checks = vec![
        GateCheck {
            id: "semantic-equality",
            label: "All application arms produce one canonical state",
            passed: evidence.semantic_results_equal,
        },
        GateCheck {
            id: "human-view-equality",
            label: "All application arms produce one complete human view",
            passed: evidence.human_views_equal,
        },
        GateCheck {
            id: "trusted-envelope",
            label: "All application arms carry one trusted envelope",
            passed: evidence.trusted_envelopes_equal,
        },
        GateCheck {
            id: "receipt-verification",
            label: "Every application receipt verifies its complete result",
            passed: evidence.receipts_verified,
        },
        GateCheck {
            id: "incremental-root-equality",
            label: "Incremental receipts equal complete rebuilds",
            passed: evidence.receipt_ablation.roots_equal,
        },
        GateCheck {
            id: "negative-cases",
            label: "All application negative cases refuse",
            passed: evidence.refusals_passed == evidence.refusals_total,
        },
        GateCheck {
            id: "deterministic-encoding",
            label: "Repeated application encoding is byte-identical",
            passed: evidence.deterministic_encodings,
        },
    ];
    HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn score(arms: &[ArmMeasurement], gate_passed: bool) -> Result<Rubric, String> {
    let tuned = arm(arms, "tuned")?;
    let wire = arm(arms, "wire")?;
    let local = arm(arms, "local")?;
    let mut checks = vec![
        reduction_check(
            "request-bytes",
            "NDABI wire request bytes",
            "at least 50% fewer",
            tuned.request_bytes as f64,
            wire.request_bytes as f64,
            0.50,
            10,
        ),
        reduction_check(
            "response-bytes",
            "NDABI wire response bytes",
            "at least 30% fewer",
            tuned.response_bytes as f64,
            wire.response_bytes as f64,
            0.30,
            10,
        ),
        reduction_check_with_intervals(
            "p95-latency",
            "NDABI wire p95 latency",
            "at least 20% lower",
            tuned,
            wire,
            0.20,
            15,
        ),
        reduction_check(
            "thread-cpu",
            "NDABI wire thread CPU",
            "at least 20% lower",
            tuned.median_thread_cpu_ns as f64,
            wire.median_thread_cpu_ns as f64,
            0.20,
            10,
        ),
        reduction_or_zero_floor_check(
            "allocated-bytes",
            "NDABI wire allocation bytes",
            "at least 40% fewer",
            tuned.allocated_bytes_per_operation,
            wire.allocated_bytes_per_operation,
            0.40,
            10,
        ),
        reduction_or_zero_floor_check(
            "allocation-count",
            "NDABI wire allocation count",
            "at least 50% fewer",
            tuned.allocations_per_operation,
            wire.allocations_per_operation,
            0.50,
            10,
        ),
        reduction_check_with_intervals(
            "local-p95-latency",
            "NDABI local p95 latency",
            "at least 50% lower",
            tuned,
            local,
            0.50,
            20,
        ),
        reduction_or_zero_floor_check(
            "local-allocated-bytes",
            "NDABI local allocation bytes",
            "at least 80% fewer",
            tuned.allocated_bytes_per_operation,
            local.allocated_bytes_per_operation,
            0.80,
            10,
        ),
        RubricCheck {
            id: "deterministic-encoding",
            label: "NDABI wire deterministic encoding",
            target: "exact repeat",
            observed: if wire.deterministic_encoding {
                "byte-identical".to_string()
            } else {
                "different bytes".to_string()
            },
            passed: wire.deterministic_encoding,
            weight: 5,
        },
    ];
    if !gate_passed {
        for check in &mut checks {
            check.passed = false;
        }
    }
    let score = checks
        .iter()
        .filter(|check| check.passed)
        .map(|check| check.weight)
        .sum();
    Ok(Rubric {
        score,
        maximum_score: 100,
        verdict: if !gate_passed {
            "invalid"
        } else {
            score_verdict(score)
        },
        comparison: "NDABI wire and local against tuned JSON",
        checks,
    })
}

fn score_white_tree(arms: &[ArmMeasurement], gate_passed: bool) -> Result<Rubric, String> {
    let tuned = arm(arms, "tuned")?;
    let wire = arm(arms, "wire")?;
    let local = arm(arms, "local")?;
    let mut checks = vec![
        reduction_check(
            "request-bytes",
            "White Tree wire request bytes",
            "at least 50% fewer",
            tuned.request_bytes as f64,
            wire.request_bytes as f64,
            0.50,
            30,
        ),
        reduction_check_with_intervals(
            "wire-p95-latency",
            "White Tree wire p95 latency",
            "no regression",
            tuned,
            wire,
            0.0,
            35,
        ),
        reduction_check_with_intervals(
            "local-p95-latency",
            "White Tree local p95 latency",
            "at least 30% lower",
            tuned,
            local,
            0.30,
            35,
        ),
    ];
    if !gate_passed {
        for check in &mut checks {
            check.passed = false;
        }
    }
    let score = checks
        .iter()
        .filter(|check| check.passed)
        .map(|check| check.weight)
        .sum();
    Ok(Rubric {
        score,
        maximum_score: 100,
        verdict: if gate_passed {
            score_verdict(score)
        } else {
            "invalid"
        },
        comparison: "White Tree NDABI wire and local against semantic JSON",
        checks,
    })
}

fn reduction_or_zero_floor_check(
    id: &'static str,
    label: &'static str,
    target: &'static str,
    control: f64,
    candidate: f64,
    required: f64,
    weight: u32,
) -> RubricCheck {
    if control == 0.0 && candidate == 0.0 {
        return RubricCheck {
            id,
            label,
            target,
            observed: "both arms reached zero".to_string(),
            passed: true,
            weight,
        };
    }
    reduction_check(id, label, target, control, candidate, required, weight)
}

fn reduction_check(
    id: &'static str,
    label: &'static str,
    target: &'static str,
    control: f64,
    candidate: f64,
    required: f64,
    weight: u32,
) -> RubricCheck {
    let reduction = reduction(control, candidate);
    let observed = if reduction >= 0.0 {
        format!("{:.1}% fewer", reduction * 100.0)
    } else {
        format!("{:.1}% more", -reduction * 100.0)
    };
    RubricCheck {
        id,
        label,
        target,
        observed,
        passed: reduction >= required,
        weight,
    }
}

fn reduction_check_with_intervals(
    id: &'static str,
    label: &'static str,
    target: &'static str,
    control: &ArmMeasurement,
    candidate: &ArmMeasurement,
    required: f64,
    weight: u32,
) -> RubricCheck {
    let mut check = reduction_check(
        id,
        label,
        target,
        control.p95_ns as f64,
        candidate.p95_ns as f64,
        required,
        weight,
    );
    check.passed = interval_target_passed(
        control.p95_ci95_low_ns,
        candidate.p95_ci95_high_ns,
        required,
    );
    check
}

fn interval_target_passed(control_low: u64, candidate_high: u64, required: f64) -> bool {
    candidate_high as f64 <= control_low as f64 * (1.0 - required)
}

fn score_verdict(score: u32) -> &'static str {
    match score {
        85..=100 => "strong support",
        65..=84 => "promising",
        40..=64 => "mixed",
        _ => "rejected",
    }
}

fn overall_verdict(
    database_gate: bool,
    database_score: u32,
    application_gate: bool,
    application_score: u32,
    white_tree_gate: bool,
    white_tree_score: u32,
) -> &'static str {
    if !database_gate || !application_gate || !white_tree_gate {
        return "invalid";
    }
    score_verdict((database_score + application_score + white_tree_score) / 3)
}

fn attribution(
    arms: &[ArmMeasurement],
    control_id: &str,
    candidate_id: &str,
) -> Result<Attribution, String> {
    let control = arm(arms, control_id)?;
    let candidate = arm(arms, candidate_id)?;
    Ok(Attribution {
        request_reduction_percent: reduction(
            control.request_bytes as f64,
            candidate.request_bytes as f64,
        ) * 100.0,
        response_reduction_percent: reduction(
            control.response_bytes as f64,
            candidate.response_bytes as f64,
        ) * 100.0,
        p95_reduction_percent: reduction(control.p95_ns as f64, candidate.p95_ns as f64) * 100.0,
        thread_cpu_reduction_percent: reduction(
            control.median_thread_cpu_ns as f64,
            candidate.median_thread_cpu_ns as f64,
        ) * 100.0,
        allocated_bytes_reduction_percent: reduction(
            control.allocated_bytes_per_operation,
            candidate.allocated_bytes_per_operation,
        ) * 100.0,
    })
}

fn local_attribution(arms: &[ArmMeasurement]) -> Result<LocalAttribution, String> {
    let tuned = arm(arms, "tuned")?;
    let local = arm(arms, "local")?;
    Ok(LocalAttribution {
        p95_reduction_percent: reduction(tuned.p95_ns as f64, local.p95_ns as f64) * 100.0,
        thread_cpu_reduction_percent: reduction(
            tuned.median_thread_cpu_ns as f64,
            local.median_thread_cpu_ns as f64,
        ) * 100.0,
        allocated_bytes_reduction_percent: reduction(
            tuned.allocated_bytes_per_operation,
            local.allocated_bytes_per_operation,
        ) * 100.0,
        allocation_count_reduction_percent: reduction(
            tuned.allocations_per_operation,
            local.allocations_per_operation,
        ) * 100.0,
    })
}

fn arm<'a>(arms: &'a [ArmMeasurement], id: &str) -> Result<&'a ArmMeasurement, String> {
    arms.iter()
        .find(|arm| arm.id == id)
        .ok_or_else(|| format!("benchmark arm is absent: {id}"))
}

fn reduction(control: f64, candidate: f64) -> f64 {
    if control == 0.0 {
        return if candidate == 0.0 { 0.0 } else { -1.0 };
    }
    1.0 - candidate / control
}

fn environment() -> Environment {
    let repository_root = command_output("git", &["rev-parse", "--show-toplevel"]);
    Environment {
        os: command_output("uname", &["-s", "-r"]),
        architecture: std::env::consts::ARCH.to_string(),
        rustc: command_output("rustc", &["--version"]),
        sqlite: sqlite::version(),
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree_state: if command_bytes("git", &["status", "--porcelain"])
            .is_some_and(|output| output.is_empty())
        {
            "clean".to_string()
        } else {
            "dirty".to_string()
        },
        olx_core_source_sha256: source_tree_sha256(&repository_root, "crates/olx-core"),
        process_peak_rss_bytes: process_peak_rss_bytes(),
    }
}

fn source_tree_sha256(repository_root: &str, path: &str) -> String {
    if repository_root == "unavailable" {
        return "unavailable".to_string();
    }
    let Some(output) = command_bytes(
        "git",
        &[
            "-C",
            repository_root,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            path,
        ],
    ) else {
        return "unavailable".to_string();
    };
    let mut paths = output
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    paths.sort_unstable();
    let mut digest = Sha256::new();
    for path_bytes in paths {
        let Ok(path_text) = std::str::from_utf8(&path_bytes) else {
            return "unavailable".to_string();
        };
        let Ok(contents) = std::fs::read(std::path::Path::new(repository_root).join(path_text))
        else {
            return "unavailable".to_string();
        };
        digest.update((path_bytes.len() as u64).to_le_bytes());
        digest.update(path_bytes);
        digest.update((contents.len() as u64).to_le_bytes());
        digest.update(contents);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn process_peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return 0;
    }
    let rss = unsafe { usage.assume_init() }.ru_maxrss;
    let rss = u64::try_from(rss).unwrap_or(0);
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss.saturating_mul(1_024)
    }
}

fn command_output(command: &str, arguments: &[&str]) -> String {
    command_bytes(command, arguments)
        .and_then(|output| String::from_utf8(output).ok())
        .map(|output| output.trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn command_bytes(command: &str, arguments: &[&str]) -> Option<Vec<u8>> {
    Command::new(command)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_thresholds_are_fixed() {
        assert_eq!(score_verdict(85), "strong support");
        assert_eq!(score_verdict(65), "promising");
        assert_eq!(score_verdict(40), "mixed");
        assert_eq!(score_verdict(39), "rejected");
    }

    #[test]
    fn argument_bounds_refuse_invalid_runs() {
        assert!(parse_args(["--rows".to_string(), "1".to_string()].into_iter()).is_err());
        assert!(parse_args(["--iterations".to_string(), "50001".to_string()].into_iter()).is_err());
        assert!(parse_args(["--iterations".to_string(), "22".to_string()].into_iter()).is_err());
    }

    #[test]
    fn overlapping_intervals_do_not_pass_a_point_estimate_target() {
        assert!(!interval_target_passed(100, 85, 0.20));
        assert!(interval_target_passed(100, 80, 0.20));
    }
}
