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
    from .export import Redactor, sanitise

    session = Path(args.session)
    log = _resolve_log(session)
    root = log.parent

    result = analyze_log(log)
    redactor = Redactor()
    # ONE sanitisation boundary. Every artifact below is a view of `safe`; a
    # second one would be a second thing to get wrong. The previous version
    # rendered report.md straight from the unredacted result.
    safe = sanitise(result, redactor)

    exporter = DatasetExporter(redactor=redactor)
    target = root / "export" / "shared"
    target.mkdir(parents=True, exist_ok=True)
    dataset_path = target / "dataset.json"
    dataset_path.write_text(
        json.dumps(exporter.build_from_sanitised(safe), indent=2,
                   ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")
    (target / "report.md").write_text(render(safe), encoding="utf-8")

    stats = redactor.stats()
    print(f"shareable dataset  {dataset_path}")
    print(f"report             {target / 'report.md'}")
    print(f"credentials removed  {stats['credentials_removed']}")
    print(f"values pseudonymised {stats['values_pseudonymised']} "
          f"({stats['distinct_pseudonyms']} distinct)")
    print("\nEvery value was classified before export. Element labels and text "
          "are not exported at all; raw bodies, screenshots, HTML snapshots "
          "and the evidence index remain in the local session directory.")
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


GENERATORS = {
    "client": ("generated_client.py", "an httpx client"),
    "playwright": ("observed_workflow.py", "a Playwright starting point"),
}


def _render_for(kind: str):
    """The renderer for one generator kind. A seam, so a test can fail it."""
    from .generate import render_client, render_playwright

    return render_client if kind == "client" else render_playwright


def cmd_generate(args: argparse.Namespace) -> int:
    """Turn the derived model into a runnable starting point."""
    from .generate import GeneratedSourceError

    session = Path(args.session)
    log = _resolve_log(session)
    root = log.parent
    result = analyze_log(log)

    filename, description = GENERATORS[args.kind]
    try:
        source = _render_for(args.kind)(result, session_name=root.name)
    except GeneratedSourceError as exc:
        # Nothing is written. A file that does not compile is worse than no
        # file: the reader discovers it three steps into a debugging session.
        raise SystemExit(str(exc)) from None

    target = Path(args.output) if args.output else root / filename
    target.write_text(source, encoding="utf-8")

    print(f"wrote {description}  {target}")
    print(f"  derived from {result.event_count} events, "
          f"{len(result.endpoints)} endpoint(s), {len(result.states)} state(s)")
    if result.auth_headers:
        print(f"  this API authenticated with: {', '.join(sorted(result.auth_headers))}")
        print("  supply them via SCRIPTSCRAP_AUTH_HEADERS; no value was captured")
    print("\nThis describes ONE observed session. Routes nobody visited are "
          "not in it.")
    return 0


def cmd_workspace(args: argparse.Namespace) -> int:
    """Serve a browsable, read-only view of one or more sessions."""
    from .workspace import SessionError, Workspace, WorkspaceConfig

    root = Path(args.session)
    try:
        workspace = Workspace(WorkspaceConfig(root=root, port=args.port))
    except SessionError as exc:
        raise SystemExit(str(exc)) from None

    unredacted = [s for s in workspace.sessions if s.redaction == "unredacted"]
    print(f"serving  {workspace.url}")
    print(f"         loopback only ({workspace.address[0]})\n")
    for handle in workspace.sessions:
        print(f"  {handle.name}  [{handle.redaction.upper()}]")
    if unredacted:
        # Said at the point of exposure, not only in a file nobody opens.
        print("\n  ⚠  This serves an unredacted capture of an authenticated session:")
        print("     live credentials, full bodies, screenshots. The page says so in")
        print("     its header. Do not screen-share without checking that.")
    print("\nCtrl+C to stop.")

    if not args.no_open:
        import webbrowser
        webbrowser.open(workspace.url)

    try:
        workspace.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        workspace.shutdown()
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

    workspace = sub.add_parser(
        "workspace", help="browse an analysed session in a local read-only viewer")
    workspace.add_argument(
        "session", help="a session directory, or a directory holding several")
    workspace.add_argument("--port", type=int, default=0,
                           help="port to listen on (default: an ephemeral one)")
    workspace.add_argument("--no-open", action="store_true",
                           help="do not open a browser")
    workspace.set_defaults(func=cmd_workspace)

    generate = sub.add_parser(
        "generate", help="derive a runnable starting point from an analysed session")
    generate.add_argument("kind", choices=sorted(GENERATORS),
                          help="client: an httpx client. playwright: a browser script.")
    generate.add_argument("session", help="session directory or events.jsonl path")
    generate.add_argument("-o", "--output", help="write here instead of the session directory")
    generate.set_defaults(func=cmd_generate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
