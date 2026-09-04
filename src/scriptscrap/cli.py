"""Command line entry points.

    scriptscrap analyze <session>   events.jsonl -> session.sqlite + report.md
    scriptscrap export  <session>   analysis     -> export/shared/

Both are OFFLINE. Neither launches a browser, which is the point: a recorded
session can be analysed and re-analysed from any machine, and deleting
`session.sqlite` and re-running `analyze` must reproduce it exactly.

Deliberately small. Argument parsing is stdlib; there is no framework here
because there are two commands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import DerivedStore, analyze_log
from .analysis.report import render
from .export import DatasetExporter


def _resolve_log(session: Path) -> Path:
    """Accept either a session directory or the event log itself."""
    if session.is_file():
        return session
    candidate = session / "events.jsonl"
    if candidate.is_file():
        return candidate
    raise SystemExit(f"no events.jsonl found at {session}")


def cmd_analyze(args: argparse.Namespace) -> int:
    session = Path(args.session)
    log = _resolve_log(session)
    root = log.parent

    result = analyze_log(log)

    db_path = root / "session.sqlite"
    if args.rebuild and db_path.exists():
        db_path.unlink()
    with DerivedStore(db_path) as store:
        run_id = store.write(result)

    analysis_dir = root / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    report_path = analysis_dir / "report.md"
    report_path.write_text(render(result), encoding="utf-8")

    print(f"analysed {result.event_count} events from {log}")
    print(f"  endpoints    {len(result.endpoints)}")
    print(f"  schemas      {len(result.schemas)}")
    print(f"  dependencies {len(result.dependencies)}")
    print(f"  ui elements  {len(result.ui_elements)}")
    print(f"  states       {len(result.states)} ({len(result.transitions)} transitions)")
    print(f"  technologies {len(result.technologies)}")
    print(f"  findings     {len(result.findings)}")
    print(f"\nderived store  {db_path} (run {run_id})")
    print(f"report         {report_path}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    session = Path(args.session)
    log = _resolve_log(session)
    root = log.parent

    result = analyze_log(log)
    exporter = DatasetExporter()
    target = root / "export" / "shared"
    dataset_path = exporter.write(result, target)
    (target / "report.md").write_text(render(result), encoding="utf-8")

    stats = exporter.redactor.stats()
    print(f"shareable dataset  {dataset_path}")
    print(f"report             {target / 'report.md'}")
    print(f"credentials removed  {stats['credentials_removed']}")
    print(f"values pseudonymised {stats['values_pseudonymised']} "
          f"({stats['distinct_pseudonyms']} distinct)")
    print("\nRaw bodies, screenshots and HTML snapshots are NOT exported; they "
          "remain in the local session directory.")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """Print the derived result as JSON, for piping."""
    result = analyze_log(_resolve_log(Path(args.session)))
    print(json.dumps(DatasetExporter().build(result), indent=2, ensure_ascii=False))
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Print the capture-health assessment for a recorded session."""
    result = analyze_log(_resolve_log(Path(args.session)))
    health = result.health or {}
    print("CAPTURE HEALTH\n")
    width = max((len(s["sensor"]) for s in health.get("sensors", [])), default=10)
    for sensor in health.get("sensors", []):
        reasons = "; ".join(sensor["reasons"])
        print(f"  {sensor['sensor']:<{width}}  {sensor['status']:<16}{reasons}")
    if health.get("notes"):
        print("\nObserved gaps:")
        for note in health["notes"]:
            print(f"  - {note}")
    print(f"\nOverall:\n  {health.get('overall', 'unknown')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scriptscrap",
        description="Offline analysis of a recorded ScriptScrap investigation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="derive knowledge from an event log")
    analyze.add_argument("session", help="session directory or events.jsonl path")
    analyze.add_argument("--rebuild", action="store_true",
                         help="delete session.sqlite first and rebuild from raw events")
    analyze.set_defaults(func=cmd_analyze)

    export = sub.add_parser("export", help="write a sanitised shareable dataset")
    export.add_argument("session", help="session directory or events.jsonl path")
    export.set_defaults(func=cmd_export)

    summary = sub.add_parser("summary", help="print the sanitised dataset as JSON")
    summary.add_argument("session", help="session directory or events.jsonl path")
    summary.set_defaults(func=cmd_summary)

    health = sub.add_parser("health", help="print the capture-health assessment")
    health.add_argument("session", help="session directory or events.jsonl path")
    health.set_defaults(func=cmd_health)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
