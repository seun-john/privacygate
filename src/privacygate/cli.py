"""Command line for PrivacyGate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .core import InputError, finding, load, report, require
from .redact import redact, restore
from .runner import Command, main_wrapper, run

MAX_BYTES = 10 * 1024 * 1024
OK = frozenset({"NO_PATTERN_MATCH", "RESTORED"})


def _read_text(path: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"Not a file: {path}")
    if p.stat().st_size > MAX_BYTES:
        raise InputError(f"{path} is larger than {MAX_BYTES // 1024 // 1024} MiB")
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise InputError(f"{path} is not valid UTF-8 text") from exc


def _summarise(text: str, terms: list[str]) -> tuple[dict[str, Any], str, dict[str, str]]:
    clean, mapping = redact(text, terms)
    kinds: dict[str, int] = {}
    for placeholder in mapping:
        kind = placeholder[1:].rsplit("_", 1)[0]
        kinds[kind] = kinds.get(kind, 0) + 1
    result = report(
        "PrivacyGate",
        [
            finding(
                "REDACTED" if mapping else "NO_PATTERN_MATCH",
                "Pattern screening is incomplete; read the output before sharing it.",
                distinct_values=len(mapping),
                by_kind=kinds,
            )
        ],
        scope="pattern matching only; names and addresses need explicit confidential terms",
    )
    return result, clean, mapping


def _scan(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    text = require(data, "text", str)
    terms = data.get("confidential_terms", [])
    if not isinstance(terms, list):
        raise InputError("'confidential_terms' must be an array")
    result, clean, _ = _summarise(text, terms)
    result["redacted_text"] = clean
    return result


def _redact_file(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    terms = list(args.term or [])
    if args.terms_file:
        terms += [t for t in _read_text(args.terms_file).splitlines() if t.strip()]
    target = Path(args.redacted_out)
    if target.resolve() == Path(args.file).resolve():
        raise InputError("--redacted-out must not overwrite the input file")
    result, clean, mapping = _summarise(_read_text(args.file), terms)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(clean, encoding="utf-8", newline="\n")
    result["redacted_file"] = str(target)
    if args.mapping_out:
        Path(args.mapping_out).write_text(json.dumps(mapping, indent=2) + "\n", encoding="utf-8")
        result["mapping_file"] = str(args.mapping_out)
        result["warning"] = "The mapping file contains the original confidential values."
    return result


def _restore_file(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    mapping = load(args.mapping)
    if not isinstance(mapping, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()
    ):
        raise InputError("The mapping must be a JSON object of placeholder to original text")
    target = Path(args.restored_out)
    if target.resolve() in {Path(args.file).resolve(), Path(args.mapping).resolve()}:
        raise InputError("--restored-out must not overwrite an input file")
    text = restore(_read_text(args.file), mapping)
    target.write_text(text, encoding="utf-8", newline="\n")
    return report(
        "PrivacyGate",
        [finding("RESTORED", "Placeholders replaced from the mapping.", restored_file=str(target))],
    )


COMMANDS = {
    "scan": Command(_scan, "Redact the text in a JSON input", OK),
    "redact": Command(
        _redact_file,
        "Redact a plain-text file and write the cleaned copy",
        OK,
        takes_input=False,
        options=[
            (("file",), {"help": "UTF-8 text file to redact"}),
            (
                ("--redacted-out", "-r"),
                {"required": True, "help": "where to write the cleaned text"},
            ),
            (("--term", "-t"), {"action": "append", "help": "confidential term (repeatable)"}),
            (("--terms-file",), {"help": "file with one confidential term per line"}),
            (
                ("--mapping-out",),
                {"help": "save placeholder-to-original mapping (contains secrets)"},
            ),
        ],
    ),
    "restore": Command(
        _restore_file,
        "Put originals back into a redacted file using a mapping",
        OK,
        takes_input=False,
        options=[
            (("file",), {"help": "redacted text file"}),
            (("--mapping", "-m"), {"required": True, "help": "mapping JSON from --mapping-out"}),
            (("--restored-out", "-r"), {"required": True, "help": "where to write the result"}),
        ],
        protect=("mapping", "file"),
    ),
}


def main(argv: list[str] | None = None) -> int:
    return run("privacygate", "Redact sensitive values before sharing text.", COMMANDS, argv)


if __name__ == "__main__":
    main_wrapper(main)
