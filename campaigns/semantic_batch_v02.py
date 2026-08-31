#!/usr/bin/env python3
"""Run the frozen NDABI semantic batch campaign v0.2."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import selectors
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "campaigns" / "results" / "semantic-batch-v02"
SPECIFICATION = ROOT / "specs" / "ndabi_semantic_batch_campaign_v0_2.md"
SOURCE_EXAMPLE = (
    ROOT
    / "crates"
    / "ndabi-postgres-v1"
    / "examples"
    / "review_batch_graph_showdown.rs"
)
RELEASE_EXAMPLE = ROOT / "target" / "release" / "examples" / "review_batch_graph_showdown"
PINNED_POSTGRES = (
    "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
)
PINNED_TOXIPROXY = (
    "ghcr.io/shopify/toxiproxy:2.12.0@"
    "sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"
)
POSTGRES_PASSWORD = "ndabi-test-only"
READER_ROLE = "ndabi_graph_reader"
READER_PASSWORD = "ndabi-graph-test-only"
ARMS = ("repeated_native", "fused_native", "ndabi_graph")
FORMAL_CELLS = (
    (1, 0, 1),
    (8, 0, 1),
    (32, 0, 1),
    (128, 0, 1),
    (256, 0, 1),
    (1024, 0, 1),
    (256, 2, 1),
    (256, 10, 1),
    (256, 40, 1),
    (256, 2, 8),
    (256, 2, 32),
)
KEY_CELL = (256, 2, 1)
MINIMUM_IDLE_PERCENT = 80.0
QUIET_CONSECUTIVE_SAMPLES = 3
QUIET_WAIT_SECONDS = 300
BUILD_NAMES = {"cargo", "rustc", "clang", "clang++", "cc1", "cc1plus"}
CAMPAIGN_PATTERN = re.compile(r"(?:validation_suite|benchmark|showdown|campaign)", re.I)


class CampaignError(RuntimeError):
    """Reject one invalid campaign without weakening its gates."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignError(message)


def command(
    arguments: list[str],
    *,
    timeout: float = 120,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=environment,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"command failed: {arguments[0]}: {detail}")
    return completed


def optional_command(arguments: list[str], *, timeout: float = 30) -> str:
    try:
        return command(arguments, timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_manifest() -> dict[str, Any]:
    selected = {"Cargo.toml", "Cargo.lock"}
    for optional in (ROOT / "rust-toolchain.toml", ROOT / "rust-toolchain"):
        if optional.is_file():
            selected.add(str(optional.relative_to(ROOT)))
    for base in (ROOT / ".cargo", ROOT / "crates", ROOT / "tools", ROOT / "specs"):
        selected.update(
            str(path.relative_to(ROOT))
            for path in base.rglob("*")
            if path.is_file()
        )
    selected.update(
        {
            str(SPECIFICATION.relative_to(ROOT)),
            str(Path(__file__).resolve().relative_to(ROOT)),
            str(SOURCE_EXAMPLE.relative_to(ROOT)),
        }
    )
    selected.update(
        str(path.relative_to(ROOT))
        for path in (ROOT / "campaigns" / "tests").glob("test_semantic_batch_v02.py")
    )
    require(selected, "the source closure is empty")
    files = {name: sha256_file(ROOT / name) for name in sorted(selected)}
    aggregate = hashlib.sha256()
    for name, digest in files.items():
        aggregate.update(name.encode())
        aggregate.update(b"\0")
        aggregate.update(digest.encode())
        aggregate.update(b"\n")
    return {"sha256": aggregate.hexdigest(), "files": files}


def clean_checkout() -> bool:
    return command(["git", "status", "--porcelain"]).stdout == ""


def build_binaries(destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=False)
    base = [
        "cargo",
        "build",
        "--release",
        "-p",
        "ndabi-postgres-v1",
        "--example",
        "review_batch_graph_showdown",
        "--locked",
    ]
    command(base, timeout=600)
    normal = destination / "review_batch_graph_showdown"
    shutil.copy2(RELEASE_EXAMPLE, normal)
    command(base + ["--features", "allocation-counting"], timeout=600)
    allocation = destination / "review_batch_graph_showdown-allocation"
    shutil.copy2(RELEASE_EXAMPLE, allocation)
    return {
        "normal": str(normal),
        "normal_sha256": sha256_file(normal),
        "allocation": str(allocation),
        "allocation_sha256": sha256_file(allocation),
        "rustc": command(["rustc", "-Vv"]).stdout.strip(),
        "cargo": command(["cargo", "-Vv"]).stdout.strip(),
    }


def host_snapshot() -> dict[str, Any]:
    process_text = command(["ps", "-axo", "pid=,ppid=,pcpu=,comm=,args="]).stdout
    process_lines = [line for line in process_text.splitlines() if line.strip()]
    return {
        "captured_unix_ns": time.time_ns(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "process_count": len(process_lines),
        "conflicts": conflicting_processes(process_text, os.getpid()),
        "thermal": optional_command(["pmset", "-g", "therm"]),
        "load_average": os.getloadavg(),
        "idle_percent": host_idle_percent(),
    }


def host_idle_percent() -> float | None:
    if sys.platform == "darwin":
        output = command(["top", "-l", "2", "-n", "0", "-s", "1"], timeout=10).stdout
        matches = re.findall(r"CPU usage:.*?([0-9.]+)% idle", output)
        return float(matches[-1]) if matches else None
    output = command(["top", "-bn2"], timeout=10, check=False).stdout
    matches = re.findall(r"([0-9.]+)\s*id", output)
    return float(matches[-1]) if matches else None


def conflicting_processes(process_text: str, own_pid: int) -> list[dict[str, Any]]:
    conflicts = []
    for line in process_text.splitlines():
        fields = line.strip().split(maxsplit=4)
        if len(fields) != 5:
            continue
        pid_text, parent_text, cpu_text, executable, arguments = fields
        try:
            pid = int(pid_text)
            parent = int(parent_text)
            cpu = float(cpu_text)
        except ValueError:
            continue
        name = Path(executable).name
        if pid == own_pid or parent == own_pid:
            continue
        if name in BUILD_NAMES or (
            CAMPAIGN_PATTERN.search(arguments) and "semantic_batch_v02.py" not in arguments
        ):
            conflicts.append({"pid": pid, "cpu_percent": cpu, "name": name})
    return conflicts


def await_quiet_host(timeout_seconds: int = QUIET_WAIT_SECONDS) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] | None = None
    qualified: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        latest = host_snapshot()
        conflicts = latest["conflicts"]
        idle = latest["idle_percent"]
        if not conflicts and idle is not None and idle >= MINIMUM_IDLE_PERCENT:
            qualified.append(latest)
            if len(qualified) == QUIET_CONSECUTIVE_SAMPLES:
                return {
                    "qualified": True,
                    "minimum_idle_percent": MINIMUM_IDLE_PERCENT,
                    "samples": qualified,
                }
        else:
            qualified.clear()
        time.sleep(1)
    require(latest is not None, "the host snapshot is absent")
    names = ", ".join(item["name"] for item in latest["conflicts"]) or "none"
    raise CampaignError(
        f"the host did not become quiet; idle={latest['idle_percent']}; conflicts={names}"
    )


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost")
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)


def docker_socket() -> str:
    candidates = [Path("/var/run/docker.sock"), Path.home() / ".docker" / "run" / "docker.sock"]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise CampaignError("the Docker Engine socket is unavailable")


def container_stats(name: str) -> dict[str, int]:
    connection = UnixHTTPConnection(docker_socket())
    connection.request("GET", f"/containers/{name}/stats?stream=false&one-shot=true")
    response = connection.getresponse()
    body = response.read()
    connection.close()
    require(response.status == 200, f"Docker stats refused {name}")
    value = json.loads(body)
    return {
        "cpu_ns": int(value["cpu_stats"]["cpu_usage"]["total_usage"]),
        "memory_bytes": int(value["memory_stats"].get("usage", 0)),
    }


def parse_published_port(container: str, internal_port: str) -> int:
    output = command(["docker", "port", container, internal_port]).stdout.strip()
    require(output, "the published Docker port is absent")
    return int(output.rsplit(":", 1)[1])


def image_exists(reference: str) -> bool:
    return command(["docker", "image", "inspect", reference], check=False).returncode == 0


def toxiproxy_request(port: int, path: str, value: dict[str, Any]) -> None:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(value, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        require(response.status in {200, 201}, "Toxiproxy refused the configuration")


def toxiproxy_delete(port: int, path: str) -> None:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            require(response.status in {200, 204}, "Toxiproxy refused the deletion")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise


@dataclass
class DockerFixture:
    suffix: str
    postgres: str = ""
    toxiproxy: str = ""
    network: str = ""
    proxy_api_port: int = 0
    proxy_port: int = 0
    pulled_toxiproxy: bool = False

    def start(self) -> None:
        self.postgres = f"ndabi-semantic-postgres-{self.suffix}"
        self.toxiproxy = f"ndabi-semantic-toxiproxy-{self.suffix}"
        self.network = f"ndabi-semantic-{self.suffix}"
        existing = set(
            command(["docker", "ps", "-a", "--format", "{{.Names}}"])
            .stdout.strip()
            .splitlines()
        )
        require(self.postgres not in existing, "the campaign PostgreSQL name already exists")
        require(self.toxiproxy not in existing, "the campaign proxy name already exists")
        self.pulled_toxiproxy = not image_exists(PINNED_TOXIPROXY)
        if not image_exists(PINNED_POSTGRES):
            command(["docker", "pull", PINNED_POSTGRES], timeout=600)
        if self.pulled_toxiproxy:
            command(["docker", "pull", PINNED_TOXIPROXY], timeout=600)
        command(["docker", "network", "create", self.network])
        command(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                self.postgres,
                "--network",
                self.network,
                "--env",
                f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
                PINNED_POSTGRES,
            ]
        )
        self._wait_postgres()
        self._seed_postgres()
        command(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                self.toxiproxy,
                "--network",
                self.network,
                "--publish",
                "127.0.0.1::8474",
                "--publish",
                "127.0.0.1::8666",
                PINNED_TOXIPROXY,
            ]
        )
        self.proxy_api_port = parse_published_port(self.toxiproxy, "8474/tcp")
        self.proxy_port = parse_published_port(self.toxiproxy, "8666/tcp")
        for _ in range(40):
            try:
                toxiproxy_request(
                    self.proxy_api_port,
                    "/proxies",
                    {
                        "name": "postgres",
                        "listen": "0.0.0.0:8666",
                        "upstream": f"{self.postgres}:5432",
                        "enabled": True,
                    },
                )
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise CampaignError("Toxiproxy did not become ready")

    def _wait_postgres(self) -> None:
        for _ in range(60):
            ready = command(
                ["docker", "exec", self.postgres, "pg_isready", "-U", "postgres"],
                check=False,
            )
            if ready.returncode == 0:
                return
            time.sleep(0.5)
        raise CampaignError("PostgreSQL did not become ready")

    def _seed_postgres(self) -> None:
        sql = f"""
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
        FROM generate_series(1,1000000) AS id;
        CREATE ROLE {READER_ROLE} LOGIN PASSWORD '{READER_PASSWORD}';
        ALTER ROLE {READER_ROLE} SET default_transaction_read_only=on;
        GRANT CONNECT ON DATABASE postgres TO {READER_ROLE};
        GRANT USAGE ON SCHEMA public TO {READER_ROLE};
        GRANT SELECT ON items TO {READER_ROLE};
        ANALYZE items;
        """
        seed_arguments = [
            "docker",
            "exec",
            self.postgres,
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ]
        for _ in range(30):
            seeded = command(seed_arguments, timeout=180, check=False)
            if seeded.returncode == 0:
                break
            detail = seeded.stderr.strip() or seeded.stdout.strip()
            transient = (
                "No such file or directory" in detail
                or "the database system is starting up" in detail
            )
            if not transient:
                raise CampaignError(f"PostgreSQL seeding failed: {detail}")
            time.sleep(1)
        else:
            raise CampaignError("PostgreSQL did not remain ready for seeding")
        refusal = command(
            [
                "docker",
                "exec",
                "--env",
                f"PGPASSWORD={READER_PASSWORD}",
                self.postgres,
                "psql",
                "-U",
                READER_ROLE,
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "UPDATE items SET score=0 WHERE id=1",
            ],
            check=False,
        )
        require(refusal.returncode != 0, "the PostgreSQL reader accepted a write")

    def set_round_trip_ms(self, round_trip_ms: int) -> None:
        require(round_trip_ms >= 0 and round_trip_ms % 2 == 0, "the round trip must be even")
        for stream in ("upstream", "downstream"):
            toxiproxy_delete(
                self.proxy_api_port,
                f"/proxies/postgres/toxics/{stream}-latency",
            )
        one_way = round_trip_ms // 2
        if one_way:
            for stream in ("upstream", "downstream"):
                toxiproxy_request(
                    self.proxy_api_port,
                    "/proxies/postgres/toxics",
                    {
                        "name": f"{stream}-latency",
                        "type": "latency",
                        "stream": stream,
                        "toxicity": 1.0,
                        "attributes": {"latency": one_way, "jitter": 0},
                    },
                )

    def reader_connection(self) -> str:
        return (
            f"host=127.0.0.1 port={self.proxy_port} user={READER_ROLE} "
            f"password={READER_PASSWORD} dbname=postgres"
        )

    def identities(self) -> dict[str, str]:
        return {
            "postgres": command(
                ["docker", "inspect", "--format", "{{.Image}}", self.postgres]
            ).stdout.strip(),
            "toxiproxy": command(
                ["docker", "inspect", "--format", "{{.Image}}", self.toxiproxy]
            ).stdout.strip(),
        }

    def cleanup(self) -> dict[str, Any]:
        for name in (self.toxiproxy, self.postgres):
            if name:
                command(["docker", "rm", "--force", name], check=False)
        if self.network:
            command(["docker", "network", "rm", self.network], check=False)
        if self.pulled_toxiproxy:
            command(["docker", "image", "rm", PINNED_TOXIPROXY], check=False)
        containers = set(
            command(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False)
            .stdout.strip()
            .splitlines()
        )
        networks = set(
            command(["docker", "network", "ls", "--format", "{{.Name}}"], check=False)
            .stdout.strip()
            .splitlines()
        )
        return {
            "containers_removed": all(
                not name or name not in containers for name in (self.toxiproxy, self.postgres)
            ),
            "network_removed": not self.network or self.network not in networks,
            "runner_pulled_proxy_image_removed": not self.pulled_toxiproxy
            or not image_exists(PINNED_TOXIPROXY),
        }


class MemoryMonitor:
    def __init__(
        self,
        containers: list[str],
        processes: list[subprocess.Popen[str]],
        enforce_quiet: bool,
    ) -> None:
        self.containers = containers
        self.processes = processes
        self.maximum_container_bytes = {name: 0 for name in containers}
        self.maximum_client_rss_bytes = 0
        self.error: str | None = None
        self.enforce_quiet = enforce_quiet
        self.conflicts: list[dict[str, Any]] = []
        self._last_process_check = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        require(not self._thread.is_alive(), "the memory monitor did not stop")
        require(self.error is None, f"the memory monitor failed: {self.error}")
        require(
            not self.enforce_quiet or not self.conflicts,
            "another build or performance campaign overlapped the measured arm",
        )

    def sample_once(self) -> None:
        for name in self.containers:
            value = container_stats(name)["memory_bytes"]
            self.maximum_container_bytes[name] = max(
                self.maximum_container_bytes[name], value
            )
        pids = [str(process.pid) for process in self.processes if process.poll() is None]
        if pids:
            result = command(["ps", "-o", "rss=", "-p", ",".join(pids)])
            rss = sum(int(value) for value in result.stdout.split()) * 1024
            self.maximum_client_rss_bytes = max(self.maximum_client_rss_bytes, rss)
        now = time.monotonic()
        if now - self._last_process_check >= 1.0:
            process_text = command(
                ["ps", "-axo", "pid=,ppid=,pcpu=,comm=,args="]
            ).stdout
            self.conflicts.extend(conflicting_processes(process_text, os.getpid()))
            self._last_process_check = now

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample_once()
            except Exception as error:
                self.error = str(error)
                self._stop.set()
                return
            self._stop.wait(0.1)


def wait_ready(processes: list[subprocess.Popen[str]], timeout: float = 60) -> None:
    selector = selectors.DefaultSelector()
    pending = set(range(len(processes)))
    for index, process in enumerate(processes):
        require(process.stderr is not None, "the worker stderr pipe is absent")
        selector.register(process.stderr, selectors.EVENT_READ, index)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for key, _ in selector.select(timeout=0.5):
            index = key.data
            line = key.fileobj.readline()
            if line == "NDABI_WORKER_READY\n":
                pending.discard(index)
                selector.unregister(key.fileobj)
            elif line:
                raise CampaignError(f"worker refused before readiness: {line.strip()}")
            elif processes[index].poll() is not None:
                raise CampaignError("a worker exited before readiness")
    selector.close()
    require(not pending, "the workers did not reach coordinated readiness")


def worker_timeout_seconds(batch_size: int, delay_ms: int, iterations: int) -> float:
    repeated_seconds = batch_size * delay_ms * iterations / 1000
    return max(60.0, repeated_seconds * 2.5 + 60.0)


def aggregate_samples(reports: list[dict[str, Any]], arm: str) -> dict[str, Any]:
    wall = []
    cpu = []
    for report in reports:
        require(report["measured_arm"] == arm, "the worker arm changed")
        require(report["coordinated"] is True, "the worker was not coordinated")
        require(report["exact_results"] is True, "the worker result changed")
        require(report["receipt_verified"] is True, "the worker receipt failed")
        wall.extend(report["raw_samples"]["wall_ns"][arm])
        cpu.extend(report["raw_samples"]["client_thread_cpu_ns"][arm])
    worker_ids = [report["worker_id"] for report in reports]
    require(
        len(set(worker_ids)) == len(worker_ids) and all(value > 0 for value in worker_ids),
        "the worker authority identifiers are not unique",
    )
    require(wall and len(wall) == len(cpu), "the raw worker samples are incomplete")
    ordered = sorted(wall)
    return {
        "samples": len(wall),
        "mean_ns": sum(wall) // len(wall),
        "p95_ns": ordered[(len(ordered) - 1) * 95 // 100],
        "client_cpu_ns": sum(cpu),
        "logical_operations": len(wall),
    }


def worker_arguments(
    binary: Path,
    arm: str,
    batch_size: int,
    iterations: int,
    warmup: int,
) -> list[str]:
    return [
        str(binary),
        "environment",
        str(batch_size),
        str(iterations),
        str(warmup),
        "--raw",
        "--coordinated",
        f"--arm={arm}",
    ]


def worker_environment(connection: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment["NDABI_TEST_READER_CONNECTION"] = connection
    return environment


def run_arm(
    binary: Path,
    fixture: DockerFixture,
    arm: str,
    batch_size: int,
    delay_ms: int,
    concurrency: int,
    iterations: int,
    warmup: int,
    enforce_quiet: bool,
) -> dict[str, Any]:
    environment = worker_environment(fixture.reader_connection())
    base_arguments = worker_arguments(binary, arm, batch_size, iterations, warmup)
    processes = [
        subprocess.Popen(
            base_arguments + [f"--worker-id={worker_id}"],
            cwd=ROOT,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        for worker_id in range(1, concurrency + 1)
    ]
    monitor: MemoryMonitor | None = None
    try:
        wait_ready(processes)
        before = {
            name: container_stats(name) for name in (fixture.postgres, fixture.toxiproxy)
        }
        monitor = MemoryMonitor(
            [fixture.postgres, fixture.toxiproxy], processes, enforce_quiet
        )
        monitor.sample_once()
        monitor.start()
        started_unix_ns = time.time_ns()
        for process in processes:
            require(process.stdin is not None, "the worker stdin pipe is absent")
            process.stdin.write("GO\n")
            process.stdin.flush()
        reports = []
        exit_codes = []
        timeout = worker_timeout_seconds(batch_size, delay_ms, iterations)
        for process in processes:
            stdout, stderr = process.communicate(timeout=timeout)
            require(process.returncode == 0, f"worker failed: {stderr.strip()}")
            exit_codes.append(process.returncode)
            reports.append(json.loads(stdout))
        finished_unix_ns = time.time_ns()
        monitor.stop()
        after = {
            name: container_stats(name) for name in (fixture.postgres, fixture.toxiproxy)
        }
    except Exception:
        for process in processes:
            if process.poll() is None:
                process.kill()
        if monitor is not None and monitor._thread.is_alive():
            monitor._stop.set()
            monitor._thread.join(timeout=5)
        raise
    require(monitor is not None, "the memory monitor was not constructed")
    aggregate = aggregate_samples(reports, arm)
    container_cpu = {
        name: after[name]["cpu_ns"] - before[name]["cpu_ns"] for name in before
    }
    require(all(value >= 0 for value in container_cpu.values()), "container CPU moved backwards")
    aggregate.update(
        {
            "arm": arm,
            "batch_size": batch_size,
            "round_trip_ms": delay_ms,
            "concurrency": concurrency,
            "iterations_per_worker": iterations,
            "started_unix_ns": started_unix_ns,
            "finished_unix_ns": finished_unix_ns,
            "container_cpu_ns": container_cpu,
            "total_container_cpu_ns": sum(container_cpu.values()),
            "complete_stack_cpu_ns": aggregate["client_cpu_ns"] + sum(container_cpu.values()),
            "maximum_container_memory_bytes": monitor.maximum_container_bytes,
            "maximum_client_rss_bytes": monitor.maximum_client_rss_bytes,
            "maximum_complete_stack_rss_bytes": monitor.maximum_client_rss_bytes
            + sum(monitor.maximum_container_bytes.values()),
            "overlap_conflicts": monitor.conflicts,
            "request_bytes": reports[0]["request_bytes"],
            "concise_json_request_bytes": reports[0]["concise_json_request_bytes"],
            "request_compression_percent": reports[0]["request_compression_percent"],
            "result_bytes": reports[0]["result_bytes"],
            "workers": reports,
            "worker_exit_codes": exit_codes,
        }
    )
    return aggregate


def compare_arms(measurements: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(set(measurements) == set(ARMS), "the comparison arms changed")
    repeated = measurements["repeated_native"]
    fused = measurements["fused_native"]
    ndabi = measurements["ndabi_graph"]
    same_results = len({item["result_bytes"] for item in measurements.values()}) == 1
    return {
        "exact_result_shape": same_results,
        "repeated_vs_ndabi_p95_speedup": repeated["p95_ns"] / ndabi["p95_ns"],
        "repeated_vs_ndabi_mean_speedup": repeated["mean_ns"] / ndabi["mean_ns"],
        "ndabi_vs_fused_p95_ratio": ndabi["p95_ns"] / fused["p95_ns"],
        "ndabi_vs_fused_mean_ratio": ndabi["mean_ns"] / fused["mean_ns"],
        "ndabi_stack_cpu_reduction_vs_repeated": 1.0
        - (
            ndabi["complete_stack_cpu_ns"] / ndabi["logical_operations"]
        )
        / (repeated["complete_stack_cpu_ns"] / repeated["logical_operations"]),
        "ndabi_allocation_request_reduction": ndabi["request_compression_percent"] / 100.0,
        "ndabi_rss_ratio_vs_fused": ndabi["maximum_complete_stack_rss_bytes"]
        / fused["maximum_complete_stack_rss_bytes"],
    }


def coefficient_of_variation(values: list[float]) -> float:
    require(values and all(value > 0 for value in values), "the variation inputs are invalid")
    return statistics.pstdev(values) / statistics.mean(values)


def evaluate_formal(repetitions: list[dict[str, Any]], allocation: dict[str, Any]) -> dict[str, Any]:
    comparisons = [cell["comparison"] for repetition in repetitions for cell in repetition["cells"]]
    key = [
        cell["comparison"]
        for repetition in repetitions
        for cell in repetition["cells"]
        if tuple(cell["cell"]) == KEY_CELL
    ]
    require(len(key) == len(repetitions), "the key performance cell is incomplete")
    allocation_values = allocation["allocation_diagnostic"]
    allocation_reduction = 1.0 - (
        allocation_values["ndabi_graph"]["allocations"]
        / allocation_values["repeated_native"]["allocations"]
    )
    gates = {
        "exact_results": all(item["exact_result_shape"] for item in comparisons),
        "fused_mean": all(item["ndabi_vs_fused_mean_ratio"] <= 1.03 for item in comparisons),
        "fused_p95": all(item["ndabi_vs_fused_p95_ratio"] <= 1.05 for item in comparisons),
        "hundred_times": all(item["repeated_vs_ndabi_p95_speedup"] >= 100 for item in key),
        "complete_stack_cpu": all(
            item["ndabi_stack_cpu_reduction_vs_repeated"] >= 0.50 for item in key
        ),
        "allocations": allocation_reduction >= 0.80,
        "rss": all(item["ndabi_rss_ratio_vs_fused"] <= 1.05 for item in comparisons),
        "request_compression": all(
            item["ndabi_allocation_request_reduction"] >= 0.60 for item in comparisons
        ),
        "repeatability": coefficient_of_variation(
            [item["ndabi_vs_fused_p95_ratio"] for item in key]
        )
        < 0.10,
    }
    return {
        "passed": all(gates.values()),
        "gates": gates,
        "allocation_reduction": allocation_reduction,
        "key_cell_p95_ratio_cv": coefficient_of_variation(
            [item["ndabi_vs_fused_p95_ratio"] for item in key]
        ),
    }


def write_json_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as destination:
        destination.write(encoded)


def compact_cell_report(cell_report: dict[str, Any]) -> dict[str, Any]:
    measurements = {}
    for arm, measurement in cell_report["measurements"].items():
        measurements[arm] = {
            key: value for key, value in measurement.items() if key != "workers"
        }
    return {
        "cell": cell_report["cell"],
        "arm_order": cell_report["arm_order"],
        "measurements": measurements,
        "comparison": cell_report["comparison"],
    }


def run_allocation(binary: Path, fixture: DockerFixture) -> dict[str, Any]:
    completed = command(
        allocation_arguments(binary),
        timeout=180,
        environment=worker_environment(fixture.reader_connection()),
    )
    value = json.loads(completed.stdout)
    require(value["allocation_diagnostic"] is not None, "allocation evidence is absent")
    return value


def allocation_arguments(binary: Path) -> list[str]:
    return [str(binary), "environment", "256", "100", "10"]


def cleanup_campaign(
    fixture: DockerFixture | None,
    binary_root: Path,
    campaign_root: Path,
    campaign_failed: bool,
) -> None:
    cleanup = {
        "containers_removed": fixture is None,
        "network_removed": fixture is None,
        "runner_pulled_proxy_image_removed": fixture is None,
    }
    errors: list[str] = []
    if fixture is not None:
        try:
            cleanup = fixture.cleanup()
        except Exception as error:
            errors.append(f"fixture cleanup failed: {type(error).__name__}: {error}")
    try:
        if binary_root.exists():
            shutil.rmtree(binary_root, ignore_errors=False)
    except Exception as error:
        errors.append(f"temporary binary cleanup failed: {type(error).__name__}: {error}")
    cleanup["temporary_binaries_removed"] = not binary_root.exists()
    if errors:
        cleanup["cleanup_errors"] = errors
    try:
        write_json_exclusive(campaign_root / "cleanup.json", cleanup)
    except Exception as error:
        errors.append(f"cleanup evidence failed: {type(error).__name__}: {error}")
    if errors and not campaign_failed:
        raise CampaignError("; ".join(errors))


def arm_order(repetition: int, cell_index: int) -> tuple[str, ...]:
    offset = (repetition + cell_index) % len(ARMS)
    return ARMS[offset:] + ARMS[:offset]


def iterations_for(arm: str, batch_size: int, delay_ms: int, smoke: bool) -> int:
    if smoke:
        return 100
    if arm == "repeated_native":
        return 200
    estimated_operation_ms = max(0.25, delay_ms + batch_size / 2_000)
    return max(200, min(20_000, int(5_000 / estimated_operation_ms)))


def run_campaign(smoke: bool) -> dict[str, Any]:
    if not smoke:
        require(clean_checkout(), "commit the complete candidate before a formal campaign")
    require(SPECIFICATION.is_file(), "the frozen campaign specification is absent")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    campaign_root = RESULT_ROOT / campaign_id
    binary_root = ROOT / "target" / "campaign-binaries" / campaign_id
    fixture: DockerFixture | None = None
    repetitions = 1 if smoke else 5
    cells = ((8, 0, 1), (8, 0, 8)) if smoke else FORMAL_CELLS
    warmup = 5 if smoke else 20
    reports: list[dict[str, Any]] = []
    allocation: dict[str, Any] | None = None
    try:
        source = source_manifest()
        binaries = build_binaries(binary_root)
        binary_evidence = {
            key: value
            for key, value in binaries.items()
            if key not in {"normal", "allocation"}
        }
        pre_host = host_snapshot() if smoke else await_quiet_host()
        fixture = DockerFixture(suffix=f"{os.getpid()}-{time.time_ns()}")
        fixture.start()
        identities = {
            "references": {
                "postgres": PINNED_POSTGRES,
                "toxiproxy": PINNED_TOXIPROXY,
            },
            "image_ids": fixture.identities(),
            "docker": command(["docker", "version", "--format", "{{json .}}"])
            .stdout.strip(),
        }
        allocation = run_allocation(Path(binaries["allocation"]), fixture)
        for repetition in range(repetitions):
            repetition_report = {"repetition": repetition + 1, "cells": []}
            for cell_index, (batch_size, delay_ms, concurrency) in enumerate(cells):
                fixture.set_round_trip_ms(delay_ms)
                measurements = {}
                order = arm_order(repetition, cell_index)
                for arm in order:
                    if not smoke:
                        await_quiet_host()
                    measurements[arm] = run_arm(
                        Path(binaries["normal"]),
                        fixture,
                        arm,
                        batch_size,
                        delay_ms,
                        concurrency,
                        iterations_for(arm, batch_size, delay_ms, smoke),
                        warmup,
                        not smoke,
                    )
                cell_report = {
                    "cell": [batch_size, delay_ms, concurrency],
                    "arm_order": order,
                    "measurements": measurements,
                    "comparison": compare_arms(measurements),
                }
                write_json_exclusive(
                    campaign_root
                    / "raw"
                    / f"r{repetition + 1}-b{batch_size}-d{delay_ms}-c{concurrency}.json",
                    cell_report,
                )
                repetition_report["cells"].append(compact_cell_report(cell_report))
            reports.append(repetition_report)
        require(allocation is not None, "the allocation report is absent")
        evaluation = None if smoke else evaluate_formal(reports, allocation)
        result = {
            "schema": "ndabi-semantic-batch-campaign-v0.2",
            "status": "smoke" if smoke else "formal",
            "campaign_id": campaign_id,
            "source": source,
            "binaries": binary_evidence,
            "containers": identities,
            "pre_host": pre_host,
            "post_host": host_snapshot(),
            "allocation": allocation,
            "repetitions": reports,
            "evaluation": evaluation,
            "limitations": [
                "The smoke mode cannot qualify performance."
                if smoke
                else "This campaign qualifies only one PostgreSQL read-only semantic batch profile.",
                "The campaign uses local Docker and controlled latency, not a geographic network.",
            ],
        }
        write_json_exclusive(campaign_root / "aggregate.json", result)
        return result
    finally:
        cleanup_campaign(
            fixture,
            binary_root,
            campaign_root,
            campaign_failed=sys.exc_info()[0] is not None,
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true")
    mode.add_argument("--formal", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        result = run_campaign(smoke=arguments.smoke)
    except (CampaignError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"campaign_id": result["campaign_id"], "status": result["status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
