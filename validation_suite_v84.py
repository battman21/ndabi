#!/usr/bin/env python3
"""Run separate-process NDABI mTLS and controlled-delay campaign v8.4."""

from __future__ import annotations

import argparse
import json
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v84"
RESULT = ROOT / "results" / "v84" / "result.json"
CONDITIONS = (
    ("local", 0.0, 500, 50),
    ("metro", 0.005, 100, 10),
    ("regional", 0.025, 40, 5),
    ("long-haul", 0.050, 20, 3),
)
MAXIMUM_UNRELATED_RUSTC_CPU_PERCENT = 25.0


def relay(source: socket.socket, target: socket.socket, delay: float) -> None:
    try:
        while True:
            payload = source.recv(65_536)
            if not payload:
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            if delay:
                time.sleep(delay)
            target.sendall(payload)
    except OSError:
        return


def run_proxy(listen: str, upstream: str, delay: float) -> int:
    listen_host, listen_port = split_address(listen)
    upstream_host, upstream_port = split_address(upstream)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(1)
        host, port = listener.getsockname()
        print(f"READY {host}:{port}", flush=True)
        client, _ = listener.accept()
        with client, socket.create_connection((upstream_host, upstream_port), timeout=10) as server:
            threads = [
                threading.Thread(target=relay, args=(client, server, delay), daemon=True),
                threading.Thread(target=relay, args=(server, client, delay), daemon=True),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
    return 0


def split_address(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError("the address must contain a host and port")
    return host, int(port)


def unrelated_rustc_cpu_percent() -> float:
    completed = subprocess.run(
        ["ps", "-axo", "%cpu=,comm="],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("the host CPU preflight failed")
    total = 0.0
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) == 2 and fields[1].endswith("/rustc"):
            total += float(fields[0])
    return total


def active_build_process_count() -> int:
    completed = subprocess.run(
        ["ps", "-axo", "comm="],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("the host process preflight failed")
    names = ("/cargo", "/cargo-tauri", "/rustc")
    return sum(line.strip().endswith(names) for line in completed.stdout.splitlines())


def monitor_build_processes(stop: threading.Event, contaminated: threading.Event) -> None:
    while not stop.wait(0.25):
        if active_build_process_count():
            contaminated.set()
            return


def ready_address(process: subprocess.Popen[str]) -> str:
    if process.stdout is None:
        raise RuntimeError("the process has no output pipe")
    ready, _, _ = select.select([process.stdout], [], [], 10)
    if not ready:
        raise RuntimeError("the process did not become ready")
    line = process.stdout.readline().strip()
    if not line.startswith("READY "):
        raise RuntimeError(f"the process failed before readiness: {line}")
    return line.removeprefix("READY ")


def openssl(arguments: list[str], directory: Path) -> None:
    completed = subprocess.run(
        ["openssl", *arguments],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "OpenSSL failed")


def make_ca(directory: Path, name: str) -> dict[str, Path]:
    key = directory / f"{name}-ca.key.pem"
    certificate = directory / f"{name}-ca.pem"
    openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN=NDABI {name} test CA",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        directory,
    )
    return {"key": key, "pem": certificate}


def make_leaf(
    directory: Path,
    ca: dict[str, Path],
    name: str,
    common_name: str,
    server: bool,
) -> dict[str, Path]:
    key_pem = directory / f"{name}.key.pem"
    request = directory / f"{name}.csr.pem"
    cert_pem = directory / f"{name}.cert.pem"
    cert_der = directory / f"{name}.cert.der"
    key_der = directory / f"{name}.key.der"
    extensions = directory / f"{name}.ext"
    extensions.write_text(
        (
            f"subjectAltName=DNS:{common_name}\n"
            f"extendedKeyUsage={'serverAuth' if server else 'clientAuth'}\n"
        ),
        encoding="utf-8",
    )
    openssl(
        [
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            str(key_pem),
            "-out",
            str(request),
        ],
        directory,
    )
    openssl(
        [
            "x509",
            "-req",
            "-days",
            "2",
            "-in",
            str(request),
            "-CA",
            str(ca["pem"]),
            "-CAkey",
            str(ca["key"]),
            "-CAcreateserial",
            "-extfile",
            str(extensions),
            "-out",
            str(cert_pem),
        ],
        directory,
    )
    openssl(["x509", "-in", str(cert_pem), "-outform", "DER", "-out", str(cert_der)], directory)
    openssl(
        ["pkcs8", "-topk8", "-nocrypt", "-in", str(key_pem), "-outform", "DER", "-out", str(key_der)],
        directory,
    )
    return {"cert": cert_der, "key": key_der}


def ca_der(directory: Path, ca: dict[str, Path], name: str) -> Path:
    output = directory / f"{name}-ca.der"
    openssl(["x509", "-in", str(ca["pem"]), "-outform", "DER", "-out", str(output)], directory)
    return output


def start_server(server: dict[str, Path], ca: Path) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [str(BINARY), "server", "127.0.0.1:0", str(server["cert"]), str(server["key"]), str(ca)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, ready_address(process)


def start_proxy(upstream: str, delay: float) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--proxy", "127.0.0.1:0", upstream, str(delay)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, ready_address(process)


def finish(process: subprocess.Popen[str], label: str) -> None:
    try:
        _, error = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        _, error = process.communicate(timeout=5)
        raise RuntimeError(f"{label} did not stop")
    if process.returncode:
        raise RuntimeError(f"{label} failed: {error.strip()}")


def measurement(
    condition: str,
    delay: float,
    iterations: int,
    warmup: int,
    surface: str,
    server_cert: dict[str, Path],
    client_cert: dict[str, Path],
    ca: Path,
) -> dict[str, Any]:
    server, server_address = start_server(server_cert, ca)
    proxy, proxy_address = start_proxy(server_address, delay)
    completed = subprocess.run(
        [
            str(BINARY),
            "client",
            proxy_address,
            surface,
            str(iterations),
            str(client_cert["cert"]),
            str(client_cert["key"]),
            str(ca),
            "ndabi.test",
            str(warmup),
        ],
        capture_output=True,
        text=True,
        timeout=max(60, int((iterations + warmup) * delay * 8 + 30)),
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "the client failed")
    finish(proxy, "the TCP proxy")
    finish(server, "the NDABI server")
    result = json.loads(completed.stdout)
    result.update(
        {
            "condition": condition,
            "one_way_delay_ms": delay * 1000,
            "approximate_rtt_ms": delay * 2000,
        }
    )
    return result


def refusal(
    server_cert: dict[str, Path],
    client_cert: dict[str, Path],
    server_ca: Path,
    client_ca: Path,
    server_name: str,
) -> dict[str, Any]:
    server, address = start_server(server_cert, server_ca)
    completed = subprocess.run(
        [
            str(BINARY),
            "client",
            address,
            "ndabi",
            "1",
            str(client_cert["cert"]),
            str(client_cert["key"]),
            str(client_ca),
            server_name,
            "0",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    try:
        _, server_error = server.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        server.terminate()
        _, server_error = server.communicate(timeout=5)
    return {
        "client_refused": completed.returncode != 0,
        "server_refused": server.returncode != 0,
        "client_error_class": tls_error_class(completed.stderr),
        "server_error_class": tls_error_class(server_error),
    }


def tls_error_class(message: str) -> str:
    lowered = message.lower()
    if "notvalidforname" in lowered or "not valid for name" in lowered:
        return "server-name"
    if "unknownissuer" in lowered or "unknown issuer" in lowered:
        return "unknown-issuer"
    if "alert" in lowered:
        return "peer-alert"
    if "certificate" in lowered:
        return "certificate"
    return "other"


def run_campaign() -> dict[str, Any]:
    if not BINARY.exists():
        raise RuntimeError("build the release ndabi_v84 binary first")
    rustc_cpu_start = unrelated_rustc_cpu_percent()
    build_processes_start = active_build_process_count()
    if rustc_cpu_start > MAXIMUM_UNRELATED_RUSTC_CPU_PERCENT or build_processes_start:
        raise RuntimeError(
            "the host is busy: "
            f"unrelated rustc CPU is {rustc_cpu_start:.1f}% and "
            f"{build_processes_start} build processes exist"
        )
    stop_monitor = threading.Event()
    contaminated = threading.Event()
    monitor = threading.Thread(
        target=monitor_build_processes,
        args=(stop_monitor, contaminated),
        daemon=True,
    )
    monitor.start()
    with tempfile.TemporaryDirectory(prefix="ndabi-v84-") as temporary:
        directory = Path(temporary)
        trusted_ca = make_ca(directory, "trusted")
        unknown_ca = make_ca(directory, "unknown")
        trusted_ca_der = ca_der(directory, trusted_ca, "trusted")
        server = make_leaf(directory, trusted_ca, "server", "ndabi.test", True)
        rotated_server = make_leaf(directory, trusted_ca, "server-rotated", "ndabi.test", True)
        client = make_leaf(directory, trusted_ca, "client", "ndabi-client", False)
        unknown_client = make_leaf(directory, unknown_ca, "unknown-client", "unknown-client", False)

        measurements = []
        for condition, delay, iterations, warmup in CONDITIONS:
            for surface in ("json", "ndabi"):
                measurements.append(
                    measurement(
                        condition,
                        delay,
                        iterations,
                        warmup,
                        surface,
                        server,
                        client,
                        trusted_ca_der,
                    )
                )
        rotation = measurement(
            "certificate-rotation",
            0.0,
            2,
            0,
            "ndabi",
            rotated_server,
            client,
            trusted_ca_der,
        )
        unknown_client = refusal(
            server,
            unknown_client,
            trusted_ca_der,
            trusted_ca_der,
            "ndabi.test",
        )
        wrong_server_name = refusal(
            server,
            client,
            trusted_ca_der,
            trusted_ca_der,
            "wrong.test",
        )

    pairs = {}
    for condition, _, _, _ in CONDITIONS:
        by_surface = {
            item["surface"]: item for item in measurements if item["condition"] == condition
        }
        pairs[condition] = {
            "ndabi_to_json_p95_ratio": by_surface["ndabi"]["p95_ns"] / by_surface["json"]["p95_ns"],
            "request_reduction_percent": (
                1 - by_surface["ndabi"]["request_bytes"] / by_surface["json"]["request_bytes"]
            )
            * 100,
        }
    functional = all(
        item["tls13"]
        and item["mutual_tls"]
        and item["transport_v02_negotiated"]
        and item["all_results_exact"]
        and item["all_receipts_verified"]
        for item in measurements
    )
    performance = all(
        pair["ndabi_to_json_p95_ratio"] <= 1.15 and pair["request_reduction_percent"] >= 40
        for pair in pairs.values()
    )
    unknown_client_refused = (
        unknown_client["client_refused"]
        and unknown_client["server_refused"]
        and unknown_client["client_error_class"] == "peer-alert"
        and unknown_client["server_error_class"] == "unknown-issuer"
    )
    wrong_server_name_refused = (
        wrong_server_name["client_refused"]
        and wrong_server_name["client_error_class"] == "server-name"
    )
    security = unknown_client_refused and wrong_server_name_refused and rotation["all_results_exact"]
    stop_monitor.set()
    monitor.join(timeout=2)
    rustc_cpu_end = unrelated_rustc_cpu_percent()
    build_processes_end = active_build_process_count()
    host_qualified = (
        not contaminated.is_set()
        and rustc_cpu_end <= MAXIMUM_UNRELATED_RUSTC_CPU_PERCENT
        and build_processes_end == 0
    )
    performance &= host_qualified
    return {
        "schema": "ndabi-remote-transport-campaign-v8.4",
        "status": "accepted" if functional and performance and security else "failed",
        "measurements": measurements,
        "comparisons": pairs,
        "security": {
            "unknown_client_ca_refused": unknown_client_refused,
            "wrong_server_name_refused": wrong_server_name_refused,
            "same_ca_server_certificate_rotation_accepted": rotation["all_results_exact"],
            "unknown_client_refusal": unknown_client,
            "wrong_server_name_refusal": wrong_server_name,
        },
        "functional_gate_passed": functional,
        "performance_gate_passed": performance,
        "security_gate_passed": security,
        "host_qualified": host_qualified,
        "unrelated_rustc_cpu_percent_start": rustc_cpu_start,
        "unrelated_rustc_cpu_percent_end": rustc_cpu_end,
        "build_processes_start": build_processes_start,
        "build_processes_end": build_processes_end,
        "build_process_observed_during_run": contaminated.is_set(),
        "boundary": (
            "Separate local processes used TLS 1.3 mTLS and controlled encrypted TCP delay. "
            "This is not a geographic WAN or production KMS custody result."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", nargs=3, metavar=("LISTEN", "UPSTREAM", "DELAY_SECONDS"))
    parser.add_argument("--output", type=Path, default=RESULT)
    arguments = parser.parse_args()
    if arguments.proxy:
        listen, upstream, delay = arguments.proxy
        return run_proxy(listen, upstream, float(delay))
    report = run_campaign()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
