"""Command line: convert scanner output and render reports.

    sentinel-findings convert --tool certwatch --in certwatch.json \
        --out findings.json [--provenance observed]

    sentinel-findings report --in findings.json --html report.html

    sentinel-findings report --in findings.json --pdf report.pdf \
        --title "Acme Q4 Assessment" --org "Acme Ltd"

    sentinel-findings merge a.json b.json --out merged.json

Exit codes: 0 ok, 1 usage/input error, 2 the honesty gate refused.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from typing import Any, List, Optional

from .adapters import ADAPTERS, convert
from .schema import Finding, FindingCollection, Provenance
from .render.html import render_html
from .render.report import render_pdf

EXIT_OK = 0
EXIT_INPUT = 1
EXIT_REFUSED = 2


def _load(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _collection_from(path: str) -> FindingCollection:
    """Read either a sentinel-findings document or a bare finding list."""
    data = _load(path)
    if isinstance(data, dict) and data.get("schema") == "sentinel-findings/1":
        return FindingCollection.from_dict(data)
    if isinstance(data, dict) and "findings" in data:
        return FindingCollection.from_dict(data)
    if isinstance(data, list):
        # Could be canonical findings already, or raw scanner rows. Canonical
        # findings have a "title"; scanner rows do not.
        if data and isinstance(data[0], dict) and "title" in data[0]:
            return FindingCollection(Finding.from_dict(r) for r in data)
        raise ValueError(
            "input looks like raw scanner output; use `convert --tool NAME` first"
        )
    raise ValueError("unrecognised input shape")


def cmd_convert(args: argparse.Namespace) -> int:
    payload = _load(args.input)
    kwargs: dict = {}
    if args.target:
        kwargs["target"] = args.target
    if args.provenance:
        kwargs["provenance"] = Provenance(args.provenance)

    try:
        findings = convert(args.tool, payload, **kwargs)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT

    collection = FindingCollection(findings)
    if not args.quiet:
        print(
            f"converted {len(findings)} raw -> {collection.total} unique "
            f"({collection.counts})",
            file=sys.stderr,
        )

    doc = collection.to_dict()
    doc["generated_at"] = _now()
    _emit(json.dumps(doc, indent=2), args.output)
    return EXIT_OK


def cmd_merge(args: argparse.Namespace) -> int:
    merged = FindingCollection()
    for path in args.inputs:
        merged.extend(_collection_from(path).sorted())
    if not args.quiet:
        print(f"merged {len(args.inputs)} file(s) -> {merged.total} unique "
              f"({merged.counts})", file=sys.stderr)
    doc = merged.to_dict()
    doc["generated_at"] = _now()
    _emit(json.dumps(doc, indent=2), args.output)
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    collection = _collection_from(args.input)

    if args.min_severity:
        from .schema import Severity

        collection = collection.filter(min_severity=Severity.parse(args.min_severity))

    if not (args.html or args.pdf):
        print("error: give --html and/or --pdf", file=sys.stderr)
        return EXIT_INPUT

    wrote = False
    if args.html:
        doc = render_html(
            collection,
            title=args.title,
            org=args.org,
            target=args.target,
            generated_at=args.generated_at or _now(human=True),
        )
        _emit(doc, args.html)
        wrote = True
        if not args.quiet:
            print(f"wrote HTML -> {args.html}", file=sys.stderr)

    if args.pdf:
        try:
            blob = render_pdf(
                collection,
                title=args.title,
                org=args.org,
                target=args.target,
                generated_at=args.generated_at or _now(human=True),
                acknowledge_simulated=args.acknowledge_simulated,
            )
        except ValueError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            print(
                "This is the honesty gate. Simulated findings cannot become a "
                "client PDF by accident. Pass --acknowledge-simulated if this "
                "is a demo and you accept it will be marked.",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        _emit_bytes(blob, args.pdf)
        wrote = True
        if not args.quiet:
            print(f"wrote PDF ({len(blob)} bytes) -> {args.pdf}", file=sys.stderr)

    return EXIT_OK if wrote else EXIT_INPUT


def cmd_summary(args: argparse.Namespace) -> int:
    collection = _collection_from(args.input)
    c = collection.counts
    print(f"total      {collection.total}")
    for sev in ("critical", "high", "medium", "low", "info"):
        print(f"{sev:10} {c[sev]}")
    if collection.simulated_count:
        print(f"simulated  {collection.simulated_count}   <-- not evidence")
    if collection.unknown_provenance_count:
        print(f"unsourced  {collection.unknown_provenance_count}   <-- no recorded origin")
    print(f"evidence   {'yes' if collection.is_pure_evidence else 'no'}")
    return EXIT_OK


def cmd_tools(_: argparse.Namespace) -> int:
    for name in sorted(ADAPTERS):
        print(name)
    return EXIT_OK


def _emit(text: str, path: Optional[str]) -> None:
    if path in (None, "-"):
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _emit_bytes(blob: bytes, path: str) -> None:
    with open(path, "wb") as fh:
        fh.write(blob)


def _now(human: bool = False) -> str:
    if human:
        return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-findings",
        description="Normalise scanner output into one schema, then render it.",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="suppress stderr chatter")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="convert one scanner's output")
    c.add_argument("--tool", required=True, choices=sorted(ADAPTERS))
    c.add_argument("--in", dest="input", required=True, help="input JSON, or - for stdin")
    c.add_argument("--out", dest="output", help="output JSON, or - for stdout")
    c.add_argument("--target", help="override the target label")
    c.add_argument(
        "--provenance",
        choices=[p.value for p in Provenance],
        help="set provenance (forgeguard adapter defaults to simulated)",
    )
    c.set_defaults(func=cmd_convert)

    m = sub.add_parser("merge", help="merge several finding documents")
    m.add_argument("inputs", nargs="+")
    m.add_argument("--out", dest="output")
    m.set_defaults(func=cmd_merge)

    r = sub.add_parser("report", help="render HTML and/or PDF")
    r.add_argument("--in", dest="input", required=True)
    r.add_argument("--html")
    r.add_argument("--pdf")
    r.add_argument("--title", default="Security Assessment")
    r.add_argument("--org", default="")
    r.add_argument("--target", default="")
    r.add_argument("--generated-at", default="")
    r.add_argument("--min-severity")
    r.add_argument(
        "--acknowledge-simulated",
        action="store_true",
        help="allow a PDF containing simulated findings (they stay marked)",
    )
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("summary", help="print counts for a findings document")
    s.add_argument("--in", dest="input", required=True)
    s.set_defaults(func=cmd_summary)

    t = sub.add_parser("tools", help="list available adapters")
    t.set_defaults(func=cmd_tools)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc.filename} not found", file=sys.stderr)
        return EXIT_INPUT
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
