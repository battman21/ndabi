#!/usr/bin/env python3
"""Serve the loopback-only NDABI benchmark laboratory."""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
RESULTS_ROOT = ROOT / "results"
BINARY = ROOT / "target" / "release" / "ndabi-showdown"
V06_BINARY = ROOT / "target" / "release" / "ndabi-v06"
TOKEN_RESULT = RESULTS_ROOT / "token-canary.json"
VALIDATION_RESULT = RESULTS_ROOT / "validation-suite.json"
V06_VALIDATION_RESULT = RESULTS_ROOT / "v06-validation-suite.json"
V07_VALIDATION_RESULT = RESULTS_ROOT / "v07-validation-suite.json"
V08_VALIDATION_RESULT = RESULTS_ROOT / "v08-validation-suite.json"
V09_VALIDATION_RESULT = RESULTS_ROOT / "v09-validation-suite.json"
DEFAULT_CONFIG = {"rows": 4096, "iterations": 2000, "warmup": 100}
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}


def validate_config(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("The benchmark configuration must be an object.")
    allowed = {"rows", "iterations", "warmup"}
    if set(value) != allowed:
        raise ValueError("The benchmark configuration has unknown or missing fields.")
    config: dict[str, int] = {}
    for name in allowed:
        item = value[name]
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"{name} must be an integer.")
        config[name] = item
    if not 256 <= config["rows"] <= 65_536:
        raise ValueError("rows must be between 256 and 65536.")
    if not 20 <= config["iterations"] <= 50_000:
        raise ValueError("iterations must be between 20 and 50000.")
    if config["iterations"] % 40 != 0:
        raise ValueError("iterations must be divisible by forty.")
    if not 0 <= config["warmup"] <= 5_000:
        raise ValueError("warmup must be between 0 and 5000.")
    return config


def run_benchmark(config: dict[str, int]) -> dict[str, object]:
    if not BINARY.is_file():
        raise RuntimeError("The release benchmark binary is absent. Run ./run.sh.")
    command = [
        str(BINARY),
        "--rows",
        str(config["rows"]),
        "--iterations",
        str(config["iterations"]),
        "--warmup",
        str(config["warmup"]),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "The benchmark process failed."
        raise RuntimeError(detail)
    result = json.loads(completed.stdout)
    if result.get("schema") != "ndabi-poc-result-v0.5":
        raise RuntimeError("The benchmark returned an unknown result schema.")
    store_result(result)
    return result


def run_v06(config: dict[str, int]) -> dict[str, object]:
    if not V06_BINARY.is_file():
        raise RuntimeError("The NDABI v0.6 binary is absent. Run ./run.sh.")
    command = [
        str(V06_BINARY),
        "--iterations",
        str(config["iterations"]),
        "--warmup",
        str(config["warmup"]),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "The NDABI v0.6 benchmark process failed."
        raise RuntimeError(detail)
    result = json.loads(completed.stdout)
    if result.get("schema") != "ndabi-poc-result-v0.6":
        raise RuntimeError("The NDABI v0.6 benchmark returned an unknown result schema.")
    store_named_result(result, RESULTS_ROOT / "v06-latest.json")
    return result


def load_token_evidence() -> dict[str, object]:
    if not TOKEN_RESULT.is_file():
        return {
            "schema": "ndabi-token-canary-v0.1",
            "status": "unavailable",
            "providers": [],
        }
    result = json.loads(TOKEN_RESULT.read_text(encoding="utf-8"))
    if result.get("schema") != "ndabi-token-canary-v0.1":
        raise RuntimeError("The token canary returned an unknown result schema.")
    return result


def load_validation_suite() -> dict[str, object]:
    if not VALIDATION_RESULT.is_file():
        return {
            "schema": "ndabi-validation-suite-v0.1",
            "status": "unavailable",
            "run_count": 0,
            "tracks": {},
        }
    result = json.loads(VALIDATION_RESULT.read_text(encoding="utf-8"))
    if result.get("schema") != "ndabi-validation-suite-v0.1":
        raise RuntimeError("The validation suite returned an unknown result schema.")
    return result


def load_v06_validation_suite() -> dict[str, object]:
    if not V06_VALIDATION_RESULT.is_file():
        return {
            "schema": "ndabi-v06-validation-suite-v0.1",
            "status": "unavailable",
            "run_count": 0,
        }
    result = json.loads(V06_VALIDATION_RESULT.read_text(encoding="utf-8"))
    if result.get("schema") != "ndabi-v06-validation-suite-v0.1":
        raise RuntimeError("The NDABI v0.6 validation suite returned an unknown result schema.")
    return result


def load_campaign_result(path: Path, schema: str) -> dict[str, object]:
    if not path.is_file():
        return {"schema": schema, "status": "unavailable"}
    result = json.loads(path.read_text(encoding="utf-8"))
    if result.get("schema") != schema:
        raise RuntimeError("The NDABI campaign returned an unknown result schema.")
    return result


def load_v07_validation_suite() -> dict[str, object]:
    return load_campaign_result(
        V07_VALIDATION_RESULT, "ndabi-v07-validation-suite-v0.1"
    )


def load_v08_validation_suite() -> dict[str, object]:
    return load_campaign_result(
        V08_VALIDATION_RESULT, "ndabi-v08-validation-suite-v0.1"
    )


def load_v09_validation_suite() -> dict[str, object]:
    return load_campaign_result(
        V09_VALIDATION_RESULT, "ndabi-v09-validation-suite-v0.1"
    )


def store_result(result: dict[str, object]) -> None:
    store_named_result(result, RESULTS_ROOT / "latest.json")


def store_named_result(result: dict[str, object], target: Path) -> None:
    RESULTS_ROOT.mkdir(exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


class LaboratoryServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], token: str):
        super().__init__(address, LaboratoryHandler)
        self.token = token
        self.run_lock = threading.Lock()
        self.latest = run_benchmark(DEFAULT_CONFIG)
        self.v06_latest = run_v06(DEFAULT_CONFIG)


class LaboratoryHandler(BaseHTTPRequestHandler):
    server: LaboratoryServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/latest":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            self.send_json(self.server.latest)
            return
        if parsed.path == "/api/v06":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            self.send_json(self.server.v06_latest)
            return
        if parsed.path == "/api/token-evidence":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_token_evidence())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/validation-suite":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_validation_suite())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/v06-validation-suite":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_v06_validation_suite())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/v07-validation-suite":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_v07_validation_suite())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/v08-validation-suite":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_v08_validation_suite())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if parsed.path == "/api/v09-validation-suite":
            if not self.authorised():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            try:
                self.send_json(load_v09_validation_suite())
            except (OSError, ValueError, RuntimeError) as error:
                self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        path = "/index.html" if parsed.path == "/" else parsed.path
        candidate = (WEB_ROOT / path.lstrip("/")).resolve()
        if WEB_ROOT.resolve() not in candidate.parents or not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = CONTENT_TYPES.get(candidate.suffix)
        if content_type is None:
            self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        self.send_bytes(candidate.read_bytes(), content_type)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/run":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not self.authorised():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                raise ValueError("The request body size is invalid.")
            config = validate_config(json.loads(self.rfile.read(length)))
            with self.server.run_lock:
                result = run_benchmark(config)
                self.server.latest = result
                self.server.v06_latest = run_v06(config)
            self.send_json(result)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def authorised(self) -> bool:
        supplied = self.headers.get("X-NDABI-Token", "")
        return secrets.compare_digest(supplied, self.server.token)

    def send_json(
        self, value: object, status: HTTPStatus = HTTPStatus.OK
    ) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, body: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
            "frame-ancestors 'none'",
        )

    def log_message(self, format_string: str, *arguments: object) -> None:
        print(f"showdown: {format_string % arguments}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--open", action="store_true")
    options = parser.parse_args()
    if not 0 <= options.port <= 65_535:
        parser.error("--port must be between 0 and 65535")

    token = secrets.token_urlsafe(24)
    server = LaboratoryServer(("127.0.0.1", options.port), token)
    url = f"http://127.0.0.1:{server.server_port}/?token={token}"
    print(f"NDABI showdown: {url}", flush=True)
    if options.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
