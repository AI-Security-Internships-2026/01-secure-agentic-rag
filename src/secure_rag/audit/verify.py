"""Offline verifier for the audit hash chain.

Usage::

    python -m secure_rag.audit.verify logs/audit.jsonl.1 logs/audit.jsonl
    kubectl logs deploy/authinject-api | python -m secure_rag.audit.verify -

Files are replayed in the order given. Lines from stdout logs may carry the ``[AUDIT] ``
prefix; any other line in a ``-`` (stdin) stream is ignored. Exit code 0 means every line
verified, 1 means the chain is broken (the first failing line is printed).

Limits: removing whole trailing lines, or a whole stdout segment of one process, is not
detectable from the log alone; ship lines to append-only storage for that.
"""

from __future__ import annotations

import argparse
import hmac
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import ValidationError

from secure_rag.audit.events import AUDIT_PREFIX, chain_hash, genesis_hash, hmac_secret
from secure_rag.audit.schema import validate_record


@dataclass
class VerifyResult:
    ok: bool
    lines: int
    segments: int
    error: str = ""
    failed_line: int | None = None


def _records(source: str, lines: Iterable[str]) -> Iterable[tuple[int, str]]:
    for number, raw in enumerate(lines, start=1):
        text = raw.rstrip("\n")
        if text.startswith(AUDIT_PREFIX):
            yield number, text[len(AUDIT_PREFIX) :]
        elif source == "-":
            continue
        elif text.strip():
            yield number, text


def verify_lines(lines: Iterable[str], secret: bytes, *, source: str = "<lines>") -> VerifyResult:
    genesis = genesis_hash(secret)
    prev: str | None = None
    count = 0
    segments = 0
    for number, text in _records(source, lines):
        count += 1
        where = f"{source}:{number}"
        try:
            record = json.loads(text)
            stored = record.pop("chain_hash")
        except (ValueError, KeyError, AttributeError, TypeError):
            return VerifyResult(False, count, segments, f"{where}: not a chained audit record", number)
        if record.get("event") == "audit.rotation_event":
            if record.get("next_chain_start") != genesis:
                return VerifyResult(False, count, segments, f"{where}: rotation event with foreign genesis", number)
            link = record.get("prev_line_hash_chain") or ""
            if prev is not None and link and link != prev:
                return VerifyResult(False, count, segments, f"{where}: segment does not link to previous line", number)
            prev = genesis
            segments += 1
        elif prev is None:
            return VerifyResult(
                False, count, segments, f"{where}: log does not start with audit.rotation_event", number
            )
        expected = chain_hash(prev, record, secret)
        if not hmac.compare_digest(expected, str(stored)):
            return VerifyResult(
                False, count, segments, f"{where}: chain hash mismatch (line altered, removed or reordered)", number
            )
        try:
            validate_record(record)
        except ValidationError as exc:
            return VerifyResult(False, count, segments, f"{where}: schema violation: {exc.errors()[0]['msg']}", number)
        prev = expected
    return VerifyResult(True, count, segments)


def verify_files(paths: list[str], secret: bytes) -> VerifyResult:
    total = 0
    segments = 0
    previous_last = ""
    for path in paths:
        if path == "-":
            lines = list(sys.stdin)
        else:
            with open(path, encoding="utf-8") as handle:
                lines = list(handle)
        result = verify_lines(lines, secret, source=path)
        if result.ok and previous_last:
            first = next((text for _, text in _records(path, lines)), None)
            link = json.loads(first).get("prev_line_hash_chain") if first else ""
            if link and link != previous_last:
                result = VerifyResult(
                    False, result.lines, result.segments, f"{path}: does not link to previous file", 1
                )
        total += result.lines
        segments += result.segments
        if not result.ok:
            return VerifyResult(False, total, segments, result.error, result.failed_line)
        last = next((text for _, text in reversed(list(_records(path, lines)))), None)
        previous_last = json.loads(last)["chain_hash"] if last else previous_last
    return VerifyResult(True, total, segments)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the HMAC hash chain of AuthInject-RAG audit logs.")
    parser.add_argument("paths", nargs="+", help="audit log files in chronological order, or - for stdin")
    args = parser.parse_args(argv)
    result = verify_files(args.paths, hmac_secret())
    if result.ok:
        print(f"OK: {result.lines} audit lines in {result.segments} segment(s) verified")
        return 0
    print(f"TAMPERED: {result.error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
