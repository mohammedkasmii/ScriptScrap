"""Turn an investigation output directory into a comparable golden snapshot.

Scope of the baseline: **every post-M0 output the investigator produces**, at a
granularity that makes a real behavioural change produce a readable diff.

Two files are summarised rather than embedded verbatim, for reasons that are
about signal, not convenience:

* `visual_traces/*.html` -- tens of KB of application markup per snapshot. The
  offline snapshot's *fidelity properties* are what matter and are asserted
  structurally; its full text is already covered by the F-03 probe.
* `events.jsonl` -- the spine is dual-write and not yet authoritative, so the
  baseline pins the emission *shape* (which event types, in which order, from
  which source) rather than payloads that will legitimately churn as sensors
  are added in M2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .normalize import normalize, sort_network_log

# Files compared field-by-field after normalisation.
FULL_COMPARE_FILES = (
    "api_dependencies.json",
    "dom_structure.json",
    "dropdown_catalogs.json",
    "jquery_events.json",
    "js_hooks_and_mutations.json",
    "mcma_openapi_spec.json",
    "out_of_scope_metadata.json",
    "session_manifest.json",
)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _summarise_html_snapshot(path: Path) -> dict[str, Any]:
    """Structural facts about an offline snapshot.

    These are exactly the properties that must not silently regress: operator
    form state present, credentials absent, offline resolution possible, and
    partial inlining visible.
    """
    html = path.read_text(encoding="utf-8")
    return {
        "has_base_tag": "<base" in html,
        "has_inlined_stylesheet": "data-scriptscrap-inlined-from" in html,
        "retains_unreadable_link": 'rel="stylesheet"' in html,
        "serialises_text_value": 'value="Alice Benali"' in html,
        "serialises_checked_state": 'checked="checked"' in html,
        "serialises_selected_option": 'selected="selected"' in html,
        "serialises_textarea_value": "Dossier 44718" in html,
        "excludes_password_value": "fixture-password-not-a-real-secret" not in html,
        "contains_shadow_host": 'id="shadow-host"' in html,
    }


def _summarise_generated_client(path: Path) -> dict[str, Any]:
    """The client's security posture and its shape, not its formatting."""
    code = path.read_text(encoding="utf-8")
    functions = sorted(
        line.split("(")[0].removeprefix("async def ").strip()
        for line in code.splitlines()
        if line.startswith("async def ")
    )
    return {
        "functions": functions,
        "reads_credentials_from_env": "SCRIPTSCRAP_AUTH_HEADERS" in code,
        "enforces_tls_verification": "verify=False" not in code and "_verify()" in code,
        "documents_credential_header_names": "credential-bearing headers" in code,
        # Values the fixture plants specifically so a leak has something to trip on.
        "embeds_no_password": "fixture-password-not-a-real-secret" not in code,
        "embeds_no_csrf_value": "FIXTURE-CSRF-TOKEN-0001" not in code,
        "embeds_no_session_cookie": "FIXTURE-SESSION-0001" not in code,
        "embeds_no_operator_pii": "Alice Benali" not in code,
        "embeds_no_captured_query_values": "?" not in code.split('url = "')[-1].split('"')[0]
        if 'url = "' in code
        else True,
    }


# Event types whose relative ORDER is genuinely nondeterministic: a page with
# two iframes loads them concurrently, so requests, responses and frame
# navigations interleave differently between runs. Their COUNTS are pinned;
# their interleaving is not, because pinning it would produce a flaky failure
# that teaches people to re-bless the baseline without reading it.
#
# Ordering is not left untested: the spine's `seq` is the authoritative total
# order, and test_replay asserts a request precedes its own response.
CONCURRENT_EVENT_TYPES = frozenset({"http_request", "http_response", "frame_navigated"})


def _summarise_events(path: Path) -> dict[str, Any]:
    """Emission shape of the dual-written event spine."""
    from scriptscrap.events import EventLogReader

    reader = EventLogReader(path)
    by_type: dict[str, int] = {}
    for event in reader:
        by_type[str(event.type)] = by_type.get(str(event.type), 0) + 1
    return {
        "problems": [str(p) for p in reader.validate()],
        "by_type": dict(sorted(by_type.items())),
        "by_source": {
            src: sum(1 for e in reader if str(e.source) == src)
            for src in sorted({str(e.source) for e in reader})
        },
        # The scripted workflow drives these sequentially, so their order IS
        # deterministic and a change to it is a real behavioural change.
        "lifecycle_order": [
            str(e.type) for e in reader if str(e.type) not in CONCURRENT_EVENT_TYPES
        ],
        "seq_is_dense": reader.sequence_gaps() == [],
        "first_type": str(reader.events[0].type) if reader.events else None,
        "last_type": str(reader.events[-1].type) if reader.events else None,
    }


def build_snapshot(output_dir: Path) -> dict[str, Any]:
    """Build the normalised, comparable representation of an investigation."""
    output_dir = Path(output_dir)
    snapshot: dict[str, Any] = {}

    snapshot["files_present"] = sorted(
        p.name for p in output_dir.iterdir() if p.is_file()
    )

    for name in FULL_COMPARE_FILES:
        path = output_dir / name
        snapshot[name] = normalize(_load_json(path)) if path.exists() else None

    network_path = output_dir / "network_traffic.json"
    if network_path.exists():
        snapshot["network_traffic.json"] = normalize(sort_network_log(_load_json(network_path)))

    client_path = output_dir / "generated_client.py"
    if client_path.exists():
        snapshot["generated_client.py"] = _summarise_generated_client(client_path)

    events_path = output_dir / "events.jsonl"
    if events_path.exists():
        snapshot["events.jsonl"] = _summarise_events(events_path)

    traces = output_dir / "visual_traces"
    if traces.is_dir():
        snapshot["visual_traces"] = {
            "screenshots": sorted(normalize(p.name) for p in traces.glob("*.png")),
            "html_snapshots": sorted(normalize(p.name) for p in traces.glob("*.html")),
            "html_properties": [
                _summarise_html_snapshot(p) for p in sorted(traces.glob("*.html"))
            ],
        }

    return snapshot


def dump(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def diff_lines(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """A readable unified diff between two snapshots."""
    import difflib

    return list(
        difflib.unified_diff(
            dump(expected).splitlines(),
            dump(actual).splitlines(),
            fromfile="golden (expected)",
            tofile="current run (actual)",
            lineterm="",
        )
    )
