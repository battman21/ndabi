#!/usr/bin/env python3
"""Run the frozen local Supavisor concurrency campaign v7.3."""

from __future__ import annotations

import hashlib
import gzip
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import cryptography

import validation_suite_v72 as v72


ROOT = Path(__file__).resolve().parent
BINARY = v72.BINARY
POSTGRES_IMAGE = v72.POSTGRES_IMAGE
POSTGREST_IMAGE = v72.POSTGREST_IMAGE
SUPAVISOR_IMAGE = v72.SUPAVISOR_IMAGE
RESULT_ROOT = ROOT / "results" / "v73"
CAMPAIGN_NAME = "NDABI Supavisor concurrency campaign v7.3"
CAMPAIGN_LABEL = "v7.3"
SESSION_PROOF_LABEL = "ndabi-v73-session-proof"
SESSION_PROOF_EXPECTED = "73"
PROCESS_COUNT = 5
SMOKE_PROCESS_COUNT = 1
SMOKE_REPEATABILITY = False
TENANT_ID = "ndabi-v73"
CONCURRENCY_LEVELS = (1, 8, 32)
OPERATIONS = 16
ROWS_PER_OPERATION = 8
WARMUPS = 3
SAMPLES = 31
SAMPLES_BY_ARM: dict[str, int] | None = None
MINIMUM_ARM_DURATION_NS = 0
MONITOR_BUILD_PROCESSES_DURING_ARM = False
BUILD_MONITOR_INTERVAL_SECONDS = 0.25
# Keep a finite deadline so a failed worker cannot hold the campaign indefinitely.
WORKER_TIMEOUT_SECONDS = 180
MAX_WORKER_START_ATTEMPTS = 3
MAX_WORKER_DIAGNOSTIC_BYTES = 4_096
WORKER_CONNECTION_ENV = "NDABI_LOAD_WORKER_CONNECTION"
BUILD_BINARY = True
REQUIRE_QUIET_HOST = True
ARMS = ("ndabi", "postgrest")
ARM_IDENTIFIERS = {
    "ndabi": "ndabi-indexed-batch-session",
    "postgrest": "postgrest-user-jwt",
}
QUERY_MULTIPLIERS = {"ndabi": 1, "postgrest": OPERATIONS}
WORKER_SCHEMA = "ndabi-supavisor-load-worker-v7.3"
MEASUREMENT_MODE = "performance"
PERFORMANCE_GATES_ENFORCED = True
SECURITY_CHECK_COUNT = 17
SMOKE_RESULT_PATH: Path | None = None
POOL_SIZE = 64
MAX_CLIENTS = 200
MINIMUM_FREE_DISK_BYTES = 10 * 1024 * 1024 * 1024
MAX_PROCESS_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_DECOMPRESSED_PROCESS_BYTES = 512 * 1024 * 1024
MINIMUM_HOST_IDLE_PERCENT = 80.0
FORBIDDEN_BUILD_PROCESSES = {
    "cargo",
    "cargo-tauri",
    "clang",
    "colima",
    "docker",
    "incus",
    "limactl",
    "rustc",
    "swiftc",
}
SOURCE_PATHS = v72.SOURCE_PATHS + (
    "../../.cargo/config.toml",
    "validation_suite_v73.py",
    "requirements-v73.txt",
    "../../specs/ndabi_supavisor_concurrency_campaign_v7_3.md",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def remove_container(name: str) -> None:
    # Remove anonymous image volumes because each campaign creates fresh database state.
    completed = command(
        "docker", "rm", "--force", "--volumes", name, check=False
    )
    if completed.returncode == 0 or "No such container" in completed.stderr:
        return
    raise RuntimeError(f"Docker could not remove the campaign container: {name}")


def cleanup_campaign(containers: tuple[str, ...], network: str) -> None:
    failures = []
    for container in containers:
        try:
            remove_container(container)
        except RuntimeError as error:
            failures.append(str(error))
    completed = command("docker", "network", "rm", network, check=False)
    if completed.returncode != 0 and "No such network" not in completed.stderr:
        failures.append(f"Docker could not remove the campaign network: {network}")
    if failures:
        raise RuntimeError("; ".join(failures))


class WorkerStartupFailure(RuntimeError):
    def __init__(self, reason: str, diagnostics: list[dict]):
        self.reason = reason
        self.diagnostics = diagnostics
        super().__init__(
            json.dumps(
                {"diagnostics": diagnostics, "reason": reason},
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def redacted_worker_stream(value: str, secrets: tuple[str, ...]) -> dict:
    redacted = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        redacted = redacted.replace(secret, "[redacted]")
    redacted = re.sub(r"(?i)(password=)[^\s]+", r"\1[redacted]", redacted)
    encoded = value.encode("utf-8")
    excerpt = redacted.encode("utf-8")[-MAX_WORKER_DIAGNOSTIC_BYTES:].decode(
        "utf-8", errors="replace"
    )
    return {
        "bytes": len(encoded),
        "excerpt": excerpt,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "truncated": len(redacted.encode("utf-8")) > MAX_WORKER_DIAGNOSTIC_BYTES,
    }


def completed_worker_diagnostics(
    processes: list[subprocess.Popen], secrets: tuple[str, ...]
) -> list[dict]:
    diagnostics = []
    for worker, process in enumerate(processes):
        if process.poll() is None:
            continue
        stdout, stderr = process.communicate(timeout=5)
        diagnostics.append(
            {
                "exit_code": process.returncode,
                "stderr": redacted_worker_stream(stderr, secrets),
                "stdout": redacted_worker_stream(stdout, secrets),
                "worker": worker,
            }
        )
    return diagnostics


def terminate_worker_diagnostics(
    processes: list[subprocess.Popen], secrets: tuple[str, ...]
) -> list[dict]:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    diagnostics = []
    for worker, process in enumerate(processes):
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        diagnostics.append(
            {
                "exit_code": process.returncode,
                "stderr": redacted_worker_stream(stderr, secrets),
                "stdout": redacted_worker_stream(stdout, secrets),
                "worker": worker,
            }
        )
    return diagnostics


def worker_connection_transport(connection: str) -> tuple[str, dict[str, str]]:
    environment = os.environ.copy()
    environment[WORKER_CONNECTION_ENV] = connection
    return f"env:{WORKER_CONNECTION_ENV}", environment


def run_with_worker_startup_retries(run_attempt) -> tuple[dict, list[dict]]:
    discarded = []
    for attempt in range(1, MAX_WORKER_START_ATTEMPTS + 1):
        try:
            return run_attempt(attempt), discarded
        except WorkerStartupFailure as error:
            discarded.append(
                {
                    "attempt": attempt,
                    "diagnostics": error.diagnostics,
                    "reason": error.reason,
                }
            )
            if attempt == MAX_WORKER_START_ATTEMPTS:
                raise RuntimeError(
                    json.dumps(
                        {"worker_startup_failures": discarded},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ) from error
            time.sleep(0.25)
    raise RuntimeError("the worker startup retry bound was not enforced")


def repository_root() -> Path:
    return Path(
        command("git", "-C", str(ROOT), "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()


def source_path(relative: str) -> Path:
    local = (ROOT / relative).resolve()
    if local.is_file():
        return local
    repository = repository_root()
    repository_relative = (repository / relative).resolve()
    if repository_relative.is_relative_to(repository) and repository_relative.is_file():
        return repository_relative
    raise FileNotFoundError(f"registered source file does not exist: {relative}")


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = source_path(relative)
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def source_matches_commit(repository: Path, commit: str) -> bool:
    for relative in SOURCE_PATHS:
        source = source_path(relative)
        try:
            repository_path = source.relative_to(repository).as_posix()
        except ValueError:
            return False
        candidate = subprocess.run(
            ["git", "show", f"{commit}:{repository_path}"],
            cwd=repository,
            check=False,
            capture_output=True,
        )
        if candidate.returncode != 0 or candidate.stdout != source.read_bytes():
            return False
    return True


def committed_source() -> str:
    repository = repository_root()
    if not tracked_worktree_clean(repository):
        raise SystemExit("commit every tracked worktree change before the campaign")
    commit = command("git", "-C", str(repository), "rev-parse", "HEAD").stdout.strip()
    if not commit or not source_matches_commit(repository, commit):
        raise SystemExit("commit every registered source file before the campaign")
    return commit


def tracked_worktree_clean(repository: Path) -> bool:
    unstaged = subprocess.run(
        ["git", "diff", "--quiet"], cwd=repository, check=False
    ).returncode
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], cwd=repository, check=False
    ).returncode
    return unstaged == 0 and staged == 0


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def percentile(values: list[int], percentage: int) -> int:
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) * percentage // 100]


def coefficient_of_variation(values: list[float]) -> float:
    mean = statistics.mean(values)
    return statistics.pstdev(values) / mean if mean else math.inf


def valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def samples_for(arm: str) -> int:
    if arm not in ARMS:
        raise ValueError("the load arm is invalid")
    if SAMPLES_BY_ARM is None:
        return SAMPLES
    samples = SAMPLES_BY_ARM.get(arm)
    if not isinstance(samples, int) or not 3 <= samples <= 10_000:
        raise ValueError("the load sample count is outside its bound")
    return samples


def expected_data_queries(arm: str, concurrency: int) -> int:
    multiplier = QUERY_MULTIPLIERS.get(arm)
    if multiplier is None:
        raise ValueError("the load arm has no query-count contract")
    return concurrency * (WARMUPS + samples_for(arm)) * multiplier


def parse_host_idle(output: str) -> float:
    matches = re.findall(r"CPU usage:.*?([0-9]+(?:\.[0-9]+)?)% idle", output)
    if not matches:
        raise RuntimeError("the host CPU idle value is unavailable")
    return float(matches[-1])


def active_build_processes() -> list[str]:
    completed = command("ps", "-Ao", "command=", check=False)
    if completed.returncode != 0:
        raise RuntimeError("the host process probe failed")
    active = {
        name
        for line in completed.stdout.splitlines()
        if (name := forbidden_process_name(line)) is not None
    }
    return sorted(active)


def forbidden_process_name(command_line: str) -> str | None:
    arguments = command_line.strip().split()
    if not arguments:
        return None
    name = Path(arguments[0]).name
    if name not in FORBIDDEN_BUILD_PROCESSES:
        return None
    if name == "docker" and arguments[1:6] == [
        "stats",
        "--all",
        "--no-trunc",
        "--no-stream",
        "--format",
    ]:
        return None
    return name


def await_quiet_host(timeout_seconds: int = 300) -> dict:
    if platform.system() != "Darwin":
        raise RuntimeError("the v7.3 host-idle gate supports macOS only")
    started = time.monotonic()
    consecutive = []
    observations = []
    while time.monotonic() - started < timeout_seconds:
        build_processes = active_build_processes()
        completed = command("top", "-l", "2", "-n", "0", "-s", "1", check=False)
        if completed.returncode != 0:
            raise RuntimeError("the host CPU idle probe failed")
        idle = parse_host_idle(completed.stdout)
        observations.append(idle)
        if idle >= MINIMUM_HOST_IDLE_PERCENT and not build_processes:
            consecutive.append(idle)
            if len(consecutive) == 3:
                return {
                    "minimum_idle_percent": min(consecutive),
                    "observations": observations,
                    "active_build_processes": [],
                    "passed": True,
                }
        else:
            consecutive.clear()
        time.sleep(1)
    raise RuntimeError("the host did not become quiet before the measured arm")


def validate_worker(report: dict, arm: str, worker: int) -> None:
    expected_arm = ARM_IDENTIFIERS[arm]
    require(report.get("schema") == WORKER_SCHEMA, "invalid worker schema")
    require(report.get("arm") == expected_arm, "invalid worker arm")
    require(report.get("worker") == worker, "invalid worker identifier")
    require(report.get("operations") == OPERATIONS, "invalid operation count")
    require(report.get("rows_per_operation") == ROWS_PER_OPERATION, "invalid row count")
    require(report.get("warmups") == WARMUPS, "invalid warm-up count")
    samples = samples_for(arm)
    require(report.get("samples") == samples, "invalid sample count")
    require(report.get("logical_operations") == samples * OPERATIONS, "invalid logical operation count")
    require(report.get("result_bytes", 0) > 0, "invalid result size")
    require(valid_digest(report.get("result_sha256")), "invalid result digest")
    require(report.get("measured_start_monotonic_ns", 0) > 0, "invalid start time")
    require(
        report.get("measured_end_monotonic_ns", 0) > report["measured_start_monotonic_ns"],
        "invalid end time",
    )
    require(report.get("total_elapsed_ns", 0) > 0, "invalid elapsed time")
    require(
        report.get("total_elapsed_ns", 0) >= MINIMUM_ARM_DURATION_NS,
        "the measured worker duration is too short",
    )
    require(report.get("total_cpu_ns", 0) > 0, "invalid CPU time")
    raw = report.get("raw_ns")
    require(
        isinstance(raw, list)
        and len(raw) == samples
        and all(isinstance(value, int) and value > 0 for value in raw),
        "invalid latency samples",
    )
    require(report.get("p50_ns") == percentile(raw, 50), "invalid worker p50")
    require(report.get("p95_ns") == percentile(raw, 95), "invalid worker p95")
    require(report.get("p99_ns") == percentile(raw, 99), "invalid worker p99")
    require(report.get("mean_allocations", -1) >= 0, "invalid allocation count")
    require(report.get("mean_allocated_bytes", -1) >= 0, "invalid allocated bytes")
    require(report.get("peak_additional_live_bytes", -1) >= 0, "invalid live bytes")
    require(report.get("passed") is True, "the worker failed")


def stop_workers(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _run_load_arm_once(
    arm: str,
    concurrency: int,
    connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
    startup_attempt: int,
) -> dict:
    samples = samples_for(arm)
    attempt_custody = custody / f"startup-attempt-{startup_attempt}"
    attempt_custody.mkdir(mode=0o700)
    ready_paths = [
        attempt_custody / f"{arm}-{concurrency}-{worker}.ready"
        for worker in range(concurrency)
    ]
    release_path = attempt_custody / f"{arm}-{concurrency}.release"
    processes: list[subprocess.Popen] = []
    monitor_stop = threading.Event()
    monitored_build_processes: set[str] = set()
    build_monitor_errors: list[str] = []

    def monitor_build_processes() -> None:
        while not monitor_stop.wait(BUILD_MONITOR_INTERVAL_SECONDS):
            try:
                monitored_build_processes.update(active_build_processes())
            except RuntimeError as error:
                build_monitor_errors.append(str(error))
                return

    monitor = None
    if MONITOR_BUILD_PROCESSES_DURING_ARM:
        monitor = threading.Thread(target=monitor_build_processes, daemon=True)
        monitor.start()
    try:
        for worker, ready_path in enumerate(ready_paths):
            start = 1_000 + worker * 3_000
            connection_argument, worker_environment = worker_connection_transport(
                connection
            )
            arguments = [
                str(BINARY),
                "--load-worker",
                arm,
                connection_argument,
                endpoint,
                str(token_path),
                str(public_key),
                v72.v71.KEY_ID,
                v72.v71.ISSUER,
                v72.v71.AUDIENCE,
                str(start),
                str(OPERATIONS),
                str(samples),
                str(worker),
                str(ready_path),
                str(release_path),
                WORKER_SCHEMA,
            ]
            processes.append(
                subprocess.Popen(
                    arguments,
                    env=worker_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        ready_started = time.monotonic()
        while not all(path.is_file() for path in ready_paths):
            failed = completed_worker_diagnostics(
                processes,
                (connection, endpoint, str(token_path), str(public_key)),
            )
            if failed:
                raise WorkerStartupFailure("worker-exited-before-release", failed)
            if time.monotonic() - ready_started > 90:
                raise WorkerStartupFailure(
                    "worker-readiness-timeout",
                    terminate_worker_diagnostics(
                        processes,
                        (connection, endpoint, str(token_path), str(public_key)),
                    ),
                )
            time.sleep(0.002)
        with release_path.open("x", encoding="utf-8"):
            pass
        reports = []
        errors = []
        for worker, process in enumerate(processes):
            try:
                stdout, stderr = process.communicate(timeout=WORKER_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                errors.append({"worker": worker, "error": "timeout"})
                continue
            if process.returncode != 0:
                errors.append(
                    {
                        "worker": worker,
                        "exit_code": process.returncode,
                        "stdout": redacted_worker_stream(
                            stdout,
                            (connection, endpoint, str(token_path), str(public_key)),
                        ),
                        "stderr": redacted_worker_stream(
                            stderr,
                            (connection, endpoint, str(token_path), str(public_key)),
                        ),
                    }
                )
                continue
            try:
                report = json.loads(stdout)
                validate_worker(report, arm, worker)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                errors.append({"worker": worker, "error": str(error)})
                continue
            reports.append(report)
    finally:
        stop_workers(processes)
        if monitor is not None:
            try:
                monitored_build_processes.update(active_build_processes())
            except RuntimeError as error:
                build_monitor_errors.append(str(error))
            monitor_stop.set()
            monitor.join(timeout=2)
            if monitor.is_alive():
                build_monitor_errors.append("the build-process monitor did not stop")
    raw_ns = [value for report in reports for value in report["raw_ns"]]
    complete = len(reports) == concurrency and not errors
    total_elapsed_ns = 0
    if reports:
        total_elapsed_ns = max(report["measured_end_monotonic_ns"] for report in reports) - min(
            report["measured_start_monotonic_ns"] for report in reports
        )
    logical_operations = sum(report["logical_operations"] for report in reports)
    throughput = (
        logical_operations * 1_000_000_000 / total_elapsed_ns if total_elapsed_ns else 0.0
    )
    return {
        "arm": arm,
        "concurrency": concurrency,
        "workers": reports,
        "errors": errors,
        "completed_workers": len(reports),
        "completed_requests": len(raw_ns),
        "logical_operations": logical_operations,
        "total_elapsed_ns": total_elapsed_ns,
        "logical_operations_per_second": throughput,
        "p50_request_ns": percentile(raw_ns, 50) if raw_ns else 0,
        "p95_request_ns": percentile(raw_ns, 95) if raw_ns else 0,
        "p99_request_ns": percentile(raw_ns, 99) if raw_ns else 0,
        "total_client_cpu_ns": sum(report["total_cpu_ns"] for report in reports),
        "mean_allocations": statistics.mean(
            [report["mean_allocations"] for report in reports]
        ) if reports else 0.0,
        "mean_allocated_bytes": statistics.mean(
            [report["mean_allocated_bytes"] for report in reports]
        ) if reports else 0.0,
        "peak_additional_live_bytes": max(
            (report["peak_additional_live_bytes"] for report in reports), default=0
        ),
        "active_build_processes_during_arm": sorted(monitored_build_processes),
        "build_monitor_errors": build_monitor_errors,
        "complete": complete,
    }


def run_load_arm(
    arm: str,
    concurrency: int,
    connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
) -> dict:
    measurement, discarded = run_with_worker_startup_retries(
        lambda attempt: _run_load_arm_once(
            arm,
            concurrency,
            connection,
            endpoint,
            token_path,
            public_key,
            custody,
            attempt,
        )
    )
    measurement["worker_startup_attempt"] = len(discarded) + 1
    measurement["discarded_worker_startup_failures"] = discarded
    return measurement


def validate_arm_measurement(measurement: dict, arm: str, concurrency: int) -> None:
    require(measurement.get("arm") == arm, "invalid measurement arm")
    require(measurement.get("concurrency") == concurrency, "invalid measurement concurrency")
    workers = measurement.get("workers")
    require(isinstance(workers, list) and len(workers) == concurrency, "invalid workers")
    require(
        sorted(worker.get("worker") for worker in workers) == list(range(concurrency)),
        "invalid worker identifiers",
    )
    for identifier, worker_report in enumerate(sorted(workers, key=lambda item: item["worker"])):
        validate_worker(worker_report, arm, identifier)
    require(measurement.get("errors") == [], "worker errors are present")
    raw_ns = [value for worker_report in workers for value in worker_report["raw_ns"]]
    require(measurement.get("completed_workers") == concurrency, "invalid completed workers")
    samples = samples_for(arm)
    require(
        measurement.get("completed_requests") == concurrency * samples,
        "invalid completed requests",
    )
    logical_operations = concurrency * samples * OPERATIONS
    require(
        measurement.get("logical_operations") == logical_operations,
        "invalid logical operations",
    )
    elapsed = max(worker_report["measured_end_monotonic_ns"] for worker_report in workers) - min(
        worker_report["measured_start_monotonic_ns"] for worker_report in workers
    )
    require(measurement.get("total_elapsed_ns") == elapsed, "invalid group elapsed time")
    require(
        measurement.get("total_elapsed_ns", 0) >= MINIMUM_ARM_DURATION_NS,
        "the measured arm duration is too short",
    )
    expected_throughput = logical_operations * 1_000_000_000 / elapsed
    require(
        math.isclose(
            measurement.get("logical_operations_per_second", 0),
            expected_throughput,
            rel_tol=1e-12,
        ),
        "invalid logical throughput",
    )
    require(measurement.get("p50_request_ns") == percentile(raw_ns, 50), "invalid group p50")
    require(measurement.get("p95_request_ns") == percentile(raw_ns, 95), "invalid group p95")
    require(measurement.get("p99_request_ns") == percentile(raw_ns, 99), "invalid group p99")
    require(
        measurement.get("total_client_cpu_ns")
        == sum(worker_report["total_cpu_ns"] for worker_report in workers),
        "invalid client CPU total",
    )
    require(
        math.isclose(
            measurement.get("mean_allocations", -1),
            statistics.mean(worker_report["mean_allocations"] for worker_report in workers),
            rel_tol=1e-12,
        ),
        "invalid mean allocations",
    )
    require(
        math.isclose(
            measurement.get("mean_allocated_bytes", -1),
            statistics.mean(worker_report["mean_allocated_bytes"] for worker_report in workers),
            rel_tol=1e-12,
        ),
        "invalid mean allocated bytes",
    )
    require(
        measurement.get("peak_additional_live_bytes")
        == max(worker_report["peak_additional_live_bytes"] for worker_report in workers),
        "invalid peak live bytes",
    )
    if MONITOR_BUILD_PROCESSES_DURING_ARM:
        require(
            measurement.get("active_build_processes_during_arm") == [],
            "a build process contaminated the measured arm",
        )
        require(
            measurement.get("build_monitor_errors") == [],
            "the build-process monitor failed",
        )
    expected_queries = expected_data_queries(arm, concurrency)
    require(
        measurement.get("expected_data_queries") == expected_queries,
        "invalid expected query count",
    )
    require(
        measurement.get("observed_data_queries") == expected_queries,
        "invalid observed query count",
    )
    require(measurement.get("query_gate_passed") is True, "the query gate failed")
    require(measurement.get("complete") is True, "the measurement is incomplete")
    host_idle = measurement.get("host_idle_preflight")
    require(isinstance(host_idle, dict), "the host-idle evidence is absent")
    require(host_idle.get("passed") is True, "the host-idle gate failed")
    if REQUIRE_QUIET_HOST:
        require(
            host_idle.get("active_build_processes") == [],
            "a build process contaminated the arm",
        )
        require(
            host_idle.get("minimum_idle_percent", 0) >= MINIMUM_HOST_IDLE_PERCENT,
            "the host-idle threshold failed",
        )
    else:
        require(
            host_idle.get("measurement_mode") == "functional-only",
            "the functional host evidence is invalid",
        )


def compare_arms(ndabi: dict, postgrest: dict) -> dict:
    require(ndabi["concurrency"] == postgrest["concurrency"], "changed concurrency")
    concurrency = ndabi["concurrency"]
    ndabi_identity = {
        report["worker"]: (report["result_bytes"], report["result_sha256"])
        for report in ndabi["workers"]
    }
    postgrest_identity = {
        report["worker"]: (report["result_bytes"], report["result_sha256"])
        for report in postgrest["workers"]
    }
    throughput_ratio = (
        ndabi["logical_operations_per_second"] / postgrest["logical_operations_per_second"]
        if postgrest["logical_operations_per_second"]
        else 0.0
    )
    p95_ratio = (
        ndabi["p95_request_ns"] / postgrest["p95_request_ns"]
        if postgrest["p95_request_ns"]
        else math.inf
    )
    throughput_target = 3.0 if concurrency == 1 else 6.0
    exact = ndabi_identity == postgrest_identity and len(ndabi_identity) == concurrency
    performance = (
        throughput_ratio >= throughput_target
        and p95_ratio <= 0.35
        and ndabi["p95_request_ns"] <= 25_000_000
    )
    passed = (
        ndabi["complete"]
        and postgrest["complete"]
        and ndabi["query_gate_passed"]
        and postgrest["query_gate_passed"]
        and exact
        and performance
    )
    return {
        "concurrency": concurrency,
        "canonical_results_equal": exact,
        "ndabi_throughput_over_postgrest": throughput_ratio,
        "ndabi_p95_to_postgrest": p95_ratio,
        "throughput_target": throughput_target,
        "p95_ratio_target": 0.35,
        "ndabi_p95_limit_ns": 25_000_000,
        "passed": passed,
    }


def validate_process_report(report: dict) -> None:
    require(isinstance(report.get("process"), int) and report["process"] > 0, "invalid process")
    cases = report.get("cases")
    require(isinstance(cases, list) and len(cases) == len(CONCURRENCY_LEVELS), "invalid cases")
    require(
        sorted(case.get("concurrency") for case in cases) == list(CONCURRENCY_LEVELS),
        "invalid concurrency cases",
    )
    for concurrency in CONCURRENCY_LEVELS:
        case = next(item for item in cases if item["concurrency"] == concurrency)
        measurements = case.get("measurements")
        require(isinstance(measurements, dict), "invalid measurements")
        require(set(measurements) == {"ndabi", "postgrest"}, "invalid measurement surfaces")
        validate_arm_measurement(measurements["ndabi"], "ndabi", concurrency)
        validate_arm_measurement(measurements["postgrest"], "postgrest", concurrency)
        expected_comparison = compare_arms(measurements["ndabi"], measurements["postgrest"])
        comparison = case.get("comparison")
        require(isinstance(comparison, dict), "invalid comparison")
        for key, value in expected_comparison.items():
            if isinstance(value, float):
                require(
                    math.isclose(comparison.get(key, math.inf), value, rel_tol=1e-12),
                    f"changed comparison: {key}",
                )
            else:
                require(comparison.get(key) == value, f"changed comparison: {key}")
        require(case.get("passed") is expected_comparison["passed"], "changed case verdict")
    require(report.get("passed") is all(case["passed"] for case in cases), "changed process verdict")


def run_process(
    process: int,
    postgres: str,
    pooled_connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
) -> dict:
    cases = []
    for concurrency in CONCURRENCY_LEVELS:
        arms = ["ndabi", "postgrest"]
        if (process + concurrency) % 2 == 0:
            arms.reverse()
        measurements = {}
        for arm in arms:
            host_idle = await_quiet_host()
            v72.psql(postgres, "SELECT pg_stat_statements_reset()")
            measurement = run_load_arm(
                arm,
                concurrency,
                pooled_connection,
                endpoint,
                token_path,
                public_key,
                custody,
            )
            observed_queries = v72.data_queries(postgres)
            expected_queries = expected_data_queries(arm, concurrency)
            measurement["observed_data_queries"] = observed_queries
            measurement["expected_data_queries"] = expected_queries
            measurement["query_gate_passed"] = observed_queries == expected_queries
            measurement["host_idle_preflight"] = host_idle
            validate_arm_measurement(measurement, arm, concurrency)
            measurements[arm] = measurement
        comparison = compare_arms(measurements["ndabi"], measurements["postgrest"])
        cases.append(
            {
                "concurrency": concurrency,
                "measurements": measurements,
                "comparison": comparison,
                "passed": comparison["passed"],
            }
        )
    return {
        "process": process,
        "cases": cases,
        "passed": all(case["passed"] for case in cases),
    }


def campaign_summary(processes: list[dict]) -> list[dict]:
    summary = []
    for concurrency in CONCURRENCY_LEVELS:
        cases = [
            next(case for case in process["cases"] if case["concurrency"] == concurrency)
            for process in processes
        ]
        ndabi = [case["measurements"]["ndabi"] for case in cases]
        postgrest = [case["measurements"]["postgrest"] for case in cases]
        comparisons = [case["comparison"] for case in cases]
        summary.append(
            {
                "concurrency": concurrency,
                "median_ndabi_logical_operations_per_second": statistics.median(
                    item["logical_operations_per_second"] for item in ndabi
                ),
                "median_postgrest_logical_operations_per_second": statistics.median(
                    item["logical_operations_per_second"] for item in postgrest
                ),
                "median_ndabi_p95_request_ns": int(
                    statistics.median(item["p95_request_ns"] for item in ndabi)
                ),
                "median_postgrest_p95_request_ns": int(
                    statistics.median(item["p95_request_ns"] for item in postgrest)
                ),
                "median_throughput_speedup": statistics.median(
                    item["ndabi_throughput_over_postgrest"] for item in comparisons
                ),
                "median_p95_ratio": statistics.median(
                    item["ndabi_p95_to_postgrest"] for item in comparisons
                ),
                "request_reduction": 1.0 - (160 + OPERATIONS * 20) / (OPERATIONS * 535),
                "database_query_reduction": 1.0 - 1.0 / OPERATIONS,
                "median_ndabi_mean_allocations": statistics.median(
                    item["mean_allocations"] for item in ndabi
                ),
                "median_ndabi_mean_allocated_bytes": statistics.median(
                    item["mean_allocated_bytes"] for item in ndabi
                ),
            }
        )
    return summary


def repeatability(processes: list[dict]) -> tuple[list[dict], bool]:
    evidence = []
    passed = True
    for concurrency in CONCURRENCY_LEVELS:
        comparisons = [
            next(case for case in process["cases"] if case["concurrency"] == concurrency)["comparison"]
            for process in processes
        ]
        throughput_cv = coefficient_of_variation(
            [item["ndabi_throughput_over_postgrest"] for item in comparisons]
        )
        p95_cv = coefficient_of_variation(
            [item["ndabi_p95_to_postgrest"] for item in comparisons]
        )
        item_passed = throughput_cv < 0.15 and p95_cv < 0.15
        evidence.append(
            {
                "concurrency": concurrency,
                "throughput_ratio_cv": throughput_cv,
                "p95_ratio_cv": p95_cv,
                "passed": item_passed,
            }
        )
        passed &= item_passed
    return evidence, passed


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_process_evidence(path: Path, value: dict) -> None:
    encoded = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
    compressed = gzip.compress(encoded, compresslevel=6, mtime=0)
    if len(compressed) > MAX_PROCESS_EVIDENCE_BYTES:
        raise RuntimeError("the compressed process evidence exceeds its size limit")
    temporary = path.with_suffix(path.suffix + ".tmp")
    if path.exists() or path.is_symlink() or temporary.exists() or temporary.is_symlink():
        raise RuntimeError("the process evidence path already exists")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(compressed)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_process_evidence(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("the compressed process evidence is not a regular file")
    try:
        with gzip.open(path, "rb") as source:
            encoded = source.read(MAX_DECOMPRESSED_PROCESS_BYTES + 1)
    except (OSError, EOFError) as error:
        raise ValueError("the compressed process evidence cannot be decoded") from error
    if len(encoded) > MAX_DECOMPRESSED_PROCESS_BYTES:
        raise ValueError("the decompressed process evidence exceeds its size limit")
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("the process evidence is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("the process evidence has an invalid shape")
    return value


def require_free_disk(path: Path, minimum_bytes: int = MINIMUM_FREE_DISK_BYTES) -> int:
    anchor = path
    while not anchor.exists() and anchor != anchor.parent:
        anchor = anchor.parent
    free = shutil.disk_usage(anchor).free
    if free < minimum_bytes:
        raise RuntimeError("the campaign host lacks the required free disk capacity")
    return free


def main() -> int:
    smoke = sys.argv[1:] == ["--smoke"]
    if sys.argv[1:] not in ([], ["--smoke"]):
        raise SystemExit("use no argument for the formal campaign or --smoke")
    parts = []
    for piece in cryptography.__version__.split("."):
        digits = "".join(character for character in piece if character.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    while len(parts) < 3:
        parts.append(0)
    if tuple(parts[:3]) < (50, 0, 0):
        raise SystemExit("cryptography must be >= 50.0.0")
    source_commit = None if smoke else committed_source()
    initial_source_sha256 = source_sha256()
    require_free_disk(RESULT_ROOT)
    latest = RESULT_ROOT / "latest.json"
    if not smoke and latest.exists():
        raise SystemExit(f"the first {CAMPAIGN_LABEL} formal campaign already exists")
    if BUILD_BINARY:
        command(
            "cargo",
            "build",
            "--manifest-path",
            str(ROOT / "Cargo.toml"),
            "--release",
            "--locked",
            "--bin",
            "ndabi_v71",
        )
    process_count = SMOKE_PROCESS_COUNT if smoke else PROCESS_COUNT
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = None if smoke else RESULT_ROOT / campaign_id
    if campaign is not None:
        campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"{TENANT_ID}-{suffix}"
    postgres = f"{TENANT_ID}-postgres-{suffix}"
    postgrest = f"{TENANT_ID}-postgrest-{suffix}"
    supavisor = f"{TENANT_ID}-supavisor-{suffix}"
    private, public_pem, jwks = v72.v71.key_material()
    expiry = int(time.time()) + 3_600
    process_reports = []
    with tempfile.TemporaryDirectory(prefix=f"{TENANT_ID}-") as temporary:
        custody = Path(temporary)
        public_key = v72.v71.write_private_file(custody, "public.pem", public_pem)
        valid_one = v72.v71.token(private, v72.v71.claims("user-1", expiry))
        valid_two = v72.v71.token(private, v72.v71.claims("user-2", expiry))
        token_paths = {
            "valid": v72.v71.write_private_file(custody, "valid.jwt", valid_one),
            "changed_signature": v72.v71.write_private_file(custody, "changed-signature.jwt", v72.v71.changed_signature(valid_one)),
            "unknown_key": v72.v71.write_private_file(custody, "unknown-key.jwt", v72.v71.token(private, v72.v71.claims("user-1", expiry), "unknown")),
            "wrong_issuer": v72.v71.write_private_file(custody, "wrong-issuer.jwt", v72.v71.token(private, v72.v71.claims("user-1", expiry, iss="https://wrong.test/auth/v1"))),
            "wrong_audience": v72.v71.write_private_file(custody, "wrong-audience.jwt", v72.v71.token(private, v72.v71.claims("user-1", expiry, aud="wrong"))),
            "expired": v72.v71.write_private_file(custody, "expired.jwt", v72.v71.token(private, v72.v71.claims("user-1", int(time.time()) - 60))),
            "unsigned_subject": v72.v71.write_private_file(custody, "unsigned-subject.jwt", v72.v71.unsigned_subject_mutation(valid_one)),
            "elevated_role": v72.v71.write_private_file(custody, "elevated-role.jwt", v72.v71.token(private, v72.v71.claims("user-1", expiry, role="service_role"))),
            "user_two": v72.v71.write_private_file(custody, "user-two.jwt", valid_two),
        }
        try:
            command("docker", "network", "create", network)
            command(
                "docker",
                "run",
                "--detach",
                "--name",
                postgres,
                "--network",
                network,
                "--publish",
                "127.0.0.1::5432",
                "--env",
                "POSTGRES_PASSWORD=ndabi-test-only",
                "--env",
                "POSTGRES_DB=ndabi",
                POSTGRES_IMAGE,
                "-c",
                "shared_preload_libraries=pg_stat_statements",
                "-c",
                "max_connections=200",
            )
            for _ in range(60):
                ready = command(
                    "docker", "exec", postgres, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("PostgreSQL did not become ready")
            role_state, rls_state = v72.setup_database(postgres)
            postgrest_port = v72.start_postgrest(
                postgrest, network, postgres, jwks, pool_size=POOL_SIZE
            )
            supavisor_port = v72.start_supavisor(
                supavisor,
                network,
                postgres,
                tenant_id=TENANT_ID,
                pool_size=POOL_SIZE,
                max_clients=MAX_CLIENTS,
            )
            pooled_connection = (
                f"host=127.0.0.1 port={supavisor_port} user=authenticator.{TENANT_ID} "
                "password=auth-test-only dbname=ndabi"
            )
            endpoint = f"http://127.0.0.1:{postgrest_port}/supabase_items"
            session_proof_passed = v72.session_proof(
                postgres,
                supavisor,
                tenant_id=TENANT_ID,
                label=SESSION_PROOF_LABEL,
                expected=SESSION_PROOF_EXPECTED,
            )
            security = v72.security_checks(
                pooled_connection, endpoint, token_paths, public_key, valid_one
            )
            security_passed = (
                len(security) == SECURITY_CHECK_COUNT and all(security.values())
            )
            for process in range(1, process_count + 1):
                report = run_process(
                    process,
                    postgres,
                    pooled_connection,
                    endpoint,
                    token_paths["valid"],
                    public_key,
                    custody,
                )
                validate_process_report(report)
                process_reports.append(report)
                if campaign is not None:
                    write_process_evidence(
                        campaign / f"process-{process}.json.gz",
                        report,
                    )
                for marker in custody.glob("*.ready"):
                    marker.unlink()
                for marker in custody.glob("*.release"):
                    marker.unlink()
            repeatability_evaluated = not smoke or SMOKE_REPEATABILITY
            repeatability_evidence, repeatability_passed = (
                repeatability(process_reports)
                if repeatability_evaluated
                else ([], False)
            )
            final_source_sha256 = source_sha256()
            source_custody_passed = final_source_sha256 == initial_source_sha256
            if source_commit is not None:
                source_custody_passed &= source_matches_commit(repository_root(), source_commit)
                source_custody_passed &= tracked_worktree_clean(repository_root())
            functional_passed = (
                role_state == "f|f|f|t"
                and rls_state == "t|t"
                and session_proof_passed
                and security_passed
                and all(report["passed"] for report in process_reports)
                and source_custody_passed
            )
            accepted = (
                not smoke
                and functional_passed
                and repeatability_passed
            )
            aggregate = {
                "campaign": CAMPAIGN_NAME,
                "campaign_id": campaign_id,
                "smoke": smoke,
                "process_count": process_count,
                "source_commit": source_commit,
                "source_sha256": final_source_sha256,
                "source_custody_passed": source_custody_passed,
                "functional_passed": functional_passed,
                "binary_sha256": file_sha256(BINARY),
                "postgres_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE).stdout.strip(),
                "postgrest_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGREST_IMAGE).stdout.strip(),
                "supavisor_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", SUPAVISOR_IMAGE).stdout.strip(),
                "concurrency_levels": list(CONCURRENCY_LEVELS),
                "operations_per_request": OPERATIONS,
                "samples_per_worker": (
                    SAMPLES
                    if SAMPLES_BY_ARM is None
                    else {arm: samples_for(arm) for arm in ARMS}
                ),
                "minimum_arm_duration_ns": MINIMUM_ARM_DURATION_NS,
                "measurement_mode": MEASUREMENT_MODE,
                "performance_gates_enforced": PERFORMANCE_GATES_ENFORCED,
                "build_process_monitor_enabled": MONITOR_BUILD_PROCESSES_DURING_ARM,
                "build_process_monitor_interval_seconds": (
                    BUILD_MONITOR_INTERVAL_SECONDS
                    if MONITOR_BUILD_PROCESSES_DURING_ARM
                    else None
                ),
                "pool_size_per_surface": POOL_SIZE,
                "pooler_mode": "session",
                "session_proof_passed": session_proof_passed,
                "authenticator_least_privilege": role_state == "f|f|f|t",
                "rls_enabled_and_forced": rls_state == "t|t",
                "security": security,
                "security_passed": security_passed,
                "repeatability": repeatability_evidence,
                "repeatability_evaluated": repeatability_evaluated,
                "repeatability_passed": repeatability_passed,
                "summary": campaign_summary(process_reports),
                "environment": {
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version(),
                    "rustc_version": command("rustc", "--version").stdout.strip(),
                    "docker_server_version": command("docker", "version", "--format", "{{.Server.Version}}").stdout.strip(),
                    "executable": sys.executable,
                },
                "accepted": accepted,
            }
            if campaign is not None:
                write_json(campaign / "aggregate.json", aggregate)
                write_json(latest, aggregate)
            elif SMOKE_RESULT_PATH is not None:
                SMOKE_RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
                if SMOKE_RESULT_PATH.is_symlink():
                    raise RuntimeError("the smoke result path is a symbolic link")
                temporary_result = SMOKE_RESULT_PATH.with_suffix(
                    SMOKE_RESULT_PATH.suffix + ".tmp"
                )
                if temporary_result.exists() or temporary_result.is_symlink():
                    raise RuntimeError("the smoke result temporary path already exists")
                write_json(temporary_result, aggregate)
                temporary_result.replace(SMOKE_RESULT_PATH)
            print(json.dumps(aggregate, indent=2))
            return 0 if (functional_passed if smoke else accepted) else 1
        finally:
            cleanup_campaign((supavisor, postgrest, postgres), network)


if __name__ == "__main__":
    raise SystemExit(main())
