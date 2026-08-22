#!/usr/bin/env python3
"""Measure provider-reported tokens for three equivalent query encodings."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


EXPECTED = "17|7|250|24"
COMMON = """You are a lossless query-decoder canary. Do not use tools.
Decode one QUERY form:
J is JSON with handle, owner, min_score, and limit integer fields.
H is H/handle/owner/min_score/limit using decimal integers.
B is B followed by four unsigned little-endian u16 integers in hexadecimal.
Return only handle|owner|min_score|limit using decimal integers.
QUERY: """
FORMS = {
    "verbose_json": 'J {"operation":"execute_prepared_query","handle":17,"arguments":{"owner":7,"min_score":250,"limit":24}}',
    "semantic_handle": "H/17/7/250/24",
    "raw_hex": "B11000700fa001800",
}
ORDERS = {
    "claude": ["verbose_json", "semantic_handle", "raw_hex"],
    "codex": ["semantic_handle", "raw_hex", "verbose_json"],
    "grok": ["raw_hex", "verbose_json", "semantic_handle"],
}


def nested_objects(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_objects(child)


def parse_json_documents(text: str) -> list[Any]:
    documents = []
    try:
        documents.append(json.loads(text))
        return documents
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if documents:
        return documents
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            document, _ = decoder.raw_decode(text, index)
            documents.append(document)
        except json.JSONDecodeError:
            continue
    return documents


def usage_from_documents(documents: list[Any]) -> dict[str, int] | None:
    candidates = []
    for document in documents:
        for value in nested_objects(document):
            usage = value.get("usage")
            if isinstance(usage, dict) and any(
                key in usage for key in ("input_tokens", "inputTokens")
            ):
                candidates.append(usage)
    if not candidates:
        return None
    usage = candidates[-1]
    input_tokens = int(usage.get("input_tokens", usage.get("inputTokens", 0)))
    output_tokens = int(usage.get("output_tokens", usage.get("outputTokens", 0)))
    cached_tokens = int(
        usage.get(
            "cache_read_input_tokens",
            usage.get("cached_input_tokens", usage.get("cachedInputTokens", 0)),
        )
    )
    cache_creation_tokens = int(usage.get("cache_creation_input_tokens", 0))
    if "cache_read_input_tokens" in usage or "cache_creation_input_tokens" in usage:
        total_input_tokens = input_tokens + cached_tokens + cache_creation_tokens
        uncached_input_tokens = input_tokens + cache_creation_tokens
    else:
        total_input_tokens = input_tokens
        uncached_input_tokens = max(0, input_tokens - cached_tokens)
    return {
        "input_tokens": total_input_tokens,
        "uncached_input_tokens": uncached_input_tokens,
        "cached_input_tokens": cached_tokens,
        "output_tokens": output_tokens,
    }


def answer_from_documents(provider: str, documents: list[Any]) -> str | None:
    if provider == "claude" and documents and isinstance(documents[0], dict):
        result = documents[0].get("result")
        if isinstance(result, str):
            return result.strip()
    if provider == "grok":
        for document in reversed(documents):
            if isinstance(document, dict) and isinstance(document.get("text"), str):
                return document["text"].strip()
    candidates = []
    for document in documents:
        for value in nested_objects(document):
            if value.get("type") in ("agent_message", "message"):
                text = value.get("text")
                if isinstance(text, str):
                    candidates.append(text)
            for key in ("output_text", "result", "response"):
                text = value.get(key)
                if isinstance(text, str):
                    candidates.append(text)
    return candidates[-1].strip() if candidates else None


def provider_command(provider: str, prompt: str) -> list[str]:
    if provider == "claude":
        return [
            "claude",
            "--print",
            "--output-format",
            "json",
            "--no-session-persistence",
            "--safe-mode",
            "--tools",
            "",
            "--permission-mode",
            "dontAsk",
            prompt,
        ]
    if provider == "codex":
        return [
            "codex",
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--sandbox",
            "read-only",
            "--json",
            prompt,
        ]
    if provider == "grok":
        return [
            "grok",
            "--single",
            prompt,
            "--output-format",
            "json",
            "--verbatim",
            "--no-memory",
            "--no-subagents",
            "--disable-web-search",
            "--tools",
            "",
            "--permission-mode",
            "dontAsk",
        ]
    raise ValueError(f"unsupported provider: {provider}")


def cli_version(provider: str) -> str:
    completed = subprocess.run(
        [provider, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    output = completed.stdout.strip() or completed.stderr.strip()
    return output.splitlines()[-1] if completed.returncode == 0 and output else "unavailable"


def run_prompt(provider: str, form: str, request: str, require_answer: bool) -> dict[str, Any]:
    prompt = COMMON + request
    started = time.monotonic_ns()
    process = subprocess.run(
        provider_command(provider, prompt),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    documents = parse_json_documents(process.stdout)
    usage = usage_from_documents(documents)
    answer = answer_from_documents(provider, documents)
    return {
        "form": form,
        "request": request,
        "request_bytes": len(request.encode("utf-8")),
        "elapsed_ms": elapsed_ms,
        "exit_code": process.returncode,
        "answer": answer,
        "answer_exact": answer == EXPECTED if require_answer else None,
        "usage": usage,
        "usage_available": usage is not None,
        "stderr_summary": process.stderr.strip()[-500:] if process.returncode else "",
    }


def provider_result(provider: str) -> dict[str, Any]:
    executable = shutil.which(provider)
    if executable is None:
        return {
            "provider": provider,
            "available": False,
            "reason": "subscription CLI is not installed",
            "forms": [],
        }
    baseline = run_prompt(provider, "empty_query_baseline", "", False)
    forms = [run_prompt(provider, form, FORMS[form], True) for form in ORDERS[provider]]
    return normalise_provider_result(
        {
            "provider": provider,
            "available": True,
            "executable": executable,
            "cli_version": cli_version(provider),
            "empty_query_baseline": baseline,
            "forms": forms,
            "all_answers_exact": all(item["answer_exact"] for item in forms),
        }
    )


def normalise_provider_result(result: dict[str, Any]) -> dict[str, Any]:
    if not result.get("available"):
        return result
    if "cli_version" not in result:
        result["cli_version"] = cli_version(result["provider"])
    forms = result["forms"]
    by_form = {item["form"]: item for item in forms}
    baseline_usage = result["empty_query_baseline"].get("usage")
    measurement_available = baseline_usage is not None and all(
        item.get("usage")
        and item["usage"]["input_tokens"] >= baseline_usage["input_tokens"]
        for item in forms
    )
    for item in forms:
        usage = item.get("usage")
        if measurement_available:
            item["representation_input_tokens"] = (
                usage["input_tokens"] - baseline_usage["input_tokens"]
            )
        else:
            item["representation_input_tokens"] = None
    verbose_tokens = by_form["verbose_json"].get("representation_input_tokens")
    compact_tokens = by_form["semantic_handle"].get("representation_input_tokens")
    representation_target_passed = None
    reduction_percent = None
    total_input_reduction_percent = None
    if verbose_tokens and compact_tokens is not None:
        reduction_percent = (verbose_tokens - compact_tokens) / verbose_tokens * 100
        representation_target_passed = reduction_percent >= 30.0
        verbose_total = by_form["verbose_json"]["usage"]["input_tokens"]
        compact_total = by_form["semantic_handle"]["usage"]["input_tokens"]
        total_input_reduction_percent = (verbose_total - compact_total) / verbose_total * 100
    result.update(
        {
            "token_measurement_available": measurement_available,
            "token_measurement_reason": (
                "provider usage supports empty-query subtraction"
                if measurement_available
                else "provider usage is absent or varies beyond the query representation"
            ),
            "representation_input_reduction_percent": reduction_percent,
            "complete_input_reduction_percent": total_input_reduction_percent,
            "target_reduction_percent": 30.0,
            "representation_target_passed": representation_target_passed,
            "preregistered_uncached_target_passed": None,
            "preregistered_uncached_target_reason": (
                "provider caching prevents a comparable uncached form measurement"
            ),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--provider",
        choices=("all", "claude", "codex", "grok"),
        default="all",
    )
    parser.add_argument("--merge-reports", nargs="+", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "token-canary.json",
    )
    arguments = parser.parse_args()
    if arguments.merge_reports:
        loaded = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in arguments.merge_reports
        ]
        results = [
            normalise_provider_result(provider)
            for report in loaded
            for provider in report.get("providers", [])
        ]
    else:
        providers = list(ORDERS) if arguments.provider == "all" else [arguments.provider]
        results = [provider_result(provider) for provider in providers]
    report = {
        "schema": "ndabi-token-canary-v0.1",
        "status": "provider-reported-canary",
        "expected_answer": EXPECTED,
        "common_prompt": COMMON,
        "providers": results,
        "limitations": [
            "Each form has one model sample.",
            "Representation tokens subtract one provider-reported empty-query baseline.",
            "Token boundaries at the query prefix can change the subtraction by one token.",
            "Prompt caching and provider defaults can change latency and uncached usage.",
            "This canary proves decoding and token accounting, not query execution.",
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if all(result.get("all_answers_exact", False) for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
