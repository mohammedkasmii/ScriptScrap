"""Markdown report over derived knowledge.

Written for a developer who has to automate the application and needs to know
how far to trust each conclusion. Every inference therefore shows its sample
count, its confidence, or both, and the caveats are stated in the body rather
than buried in a footnote -- a reader who skims must not come away thinking the
state graph is complete or that an enum candidate is an enum.
"""

from __future__ import annotations

from typing import Any

from .models import AnalysisResult

MAX_ROWS = 40


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["_none observed_", ""]
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows[:MAX_ROWS])
    if len(rows) > MAX_ROWS:
        # Say it plainly. A truncated table read as a complete one is how the
        # audit's run3 export looked safe: the two elements carrying a password
        # and a table of names sat at rows 41 and 80.
        out.append(f"| _{len(rows) - MAX_ROWS} more rows not shown_ |"
                   + " |" * (len(headers) - 1))
    out.append("")
    return out


def _why(sensor: dict[str, Any]) -> str:
    """Why a sensor is in the state it is, from whichever form is present.

    A local report has the prose. A sanitised one has only how many reasons
    there were, because each is a derived string rather than a fixed constant.
    """
    reasons = sensor.get("reasons")
    if reasons:
        return "; ".join(reasons)
    count = sensor.get("reasons_count")
    return f"{count} reason(s), text not exported" if count else "-"


def render(result: AnalysisResult) -> str:
    lines: list[str] = [
        "# ScriptScrap investigation report",
        "",
        f"- Session: `{result.session_id}`",
        f"- Events analysed: {result.event_count}",
        f"- Analysis version: {result.analysis_version}",
        "",
        "> Everything below is **derived** from recorded evidence, not observed "
        "directly. Each conclusion carries a sample count or a confidence score, "
        "and cites the raw `event_id`s that support it in the machine-readable "
        "dataset. A human drove the session, so absence of evidence here means "
        "*not observed*, never *not present*.",
        "",
    ]

    # -- technologies ------------------------------------------------------
    lines += ["## Technologies", ""]
    lines += _table(
        ["Technology", "Category", "Confidence", "Signals"],
        [[t.name, t.category, f"{t.confidence:.2f}", ", ".join(t.signals[:3]) or "—"]
         for t in result.technologies],
    )

    # -- endpoints ---------------------------------------------------------
    lines += ["## Endpoints", ""]
    rows = []
    for e in result.endpoints:
        params = ", ".join(
            f"{p.name}:{p.inferred_type}" + (f" ({p.distinct_values} distinct)"
                                             if p.distinct_values > 1 else "")
            for p in e.params
        ) or "—"
        statuses = ", ".join(f"{k}×{v}" for k, v in e.statuses.items()) or "—"
        rows.append([f"`{e.key}`", e.kind, e.observation_count, statuses, params,
                     f"{e.confidence:.2f}"])
    lines += _table(
        ["Endpoint", "Kind", "Obs", "Statuses", "Parameters", "Conf"], rows)

    templated = [e for e in result.endpoints if e.templated]
    if templated:
        lines += ["### Templated routes", "",
                  "Concrete paths are retained; templating is reversible.", ""]
        for e in templated:
            lines.append(f"- `{e.key}` ← {', '.join('`' + p + '`' for p in e.concrete_paths[:6])}")
        lines.append("")

    graphql = [e for e in result.endpoints if e.kind == "graphql"]
    if graphql:
        lines += ["## GraphQL operations", ""]
        lines += _table(
            ["Operation", "Type", "Obs", "Persisted hash"],
            [[e.graphql_operation or "—", e.graphql_operation_type or "—",
              e.observation_count, e.persisted_query_hash or "—"] for e in graphql],
        )

    # -- schemas -----------------------------------------------------------
    lines += ["## Inferred schemas", "",
              "`observed_optional` means the field was absent in at least one "
              "sample. A field present in every sample is **not** proof of "
              "requiredness. `enum_candidate` is a small observed value set, not "
              "a declared enum.", ""]
    for schema in result.schemas:
        title = f"{schema.endpoint_key} — {schema.direction}"
        if schema.status:
            title += f" ({schema.status})"
        lines += [f"### `{title}`", "",
                  f"Root `{schema.root_type}`, {schema.sample_count} sample(s)", ""]
        lines += _table(
            ["Field", "Type", "Present", "Values", "Optional", "Format", "Enum candidate"],
            [[f"`{f.path}`", f.inferred_type, f"{f.present_count}/{f.sample_count}",
              str(f.occurrence_count),
              "yes" if f.observed_optional else "—", f.inferred_format or "—",
              ", ".join(f.enum_candidate[:5]) if f.enum_candidate else "—"]
             for f in schema.fields],
        )

    # -- dependencies ------------------------------------------------------
    lines += ["## Dependencies", "",
              "Hypotheses ranked by an evidence vector, not proofs. Cross-sensor "
              "ordering is established from timestamps, never from ingest order.", ""]
    rows = []
    for d in result.dependencies:
        signals = d.evidence.signals
        why = ", ".join(filter(None, [
            "unique value" if signals.get("unique_value_match") else None,
            f"name sim {signals.get('field_name_similarity')}"
            if signals.get("field_name_similarity") else None,
            f"order:{signals.get('ordering_method')}",
            f"×{d.repeat_count}" if d.repeat_count > 1 else None,
        ]))
        rows.append([f"`{d.source_endpoint} {d.source_field}`",
                     f"`{d.target_endpoint} {d.target_field}`",
                     d.mechanism, f"{d.confidence:.2f}", why])
    lines += _table(["Source", "Target", "Mechanism", "Conf", "Evidence"], rows)

    # -- selectors ---------------------------------------------------------
    lines += ["## Interactive elements", "",
              "Stability is measured across repeated observations. An `id` is not "
              "preferred by default: a framework-generated id is often the least "
              "stable locator on the page.", ""]
    rows = []
    for u in result.ui_elements:
        rec = u.recommended
        alternatives = ", ".join(
            f"{loc.strategy} {loc.resolved_count}/{loc.sample_count}"
            for loc in u.locators[:4]
        )
        rows.append([f"`{u.tag}`", u.label or u.text or "—",
                     f"`{rec.strategy}` → `{rec.value}`" if rec else "—",
                     f"{rec.stability:.2f}" if rec else "—",
                     u.observation_count, alternatives])
    lines += _table(
        ["Tag", "Name", "Recommended locator", "Stability", "Obs", "Measured"], rows)

    unstable = [u for u in result.ui_elements
                if any(loc.warning and loc.strategy == "id" for loc in u.locators)]
    if unstable:
        lines += ["### Unstable identifiers", ""]
        for u in unstable:
            warning = next(loc.warning for loc in u.locators if loc.strategy == "id")
            lines.append(f"- `{u.label or u.text or u.tag}` — {warning}")
        lines.append("")

    # -- states ------------------------------------------------------------
    lines += ["## Observed states", "",
              "**These are the states this session visited.** The graph is not the "
              "application's state machine and makes no completeness claim.", ""]
    lines += _table(
        ["State", "Route", "Forms", "Obs"],
        [[s.label, f"`{s.url_pattern}`", ", ".join(s.forms) or "—", s.observation_count]
         for s in result.states],
    )
    if result.transitions:
        lines += ["### Transitions", ""]
        lines += _table(
            ["From", "To", "Trigger", "Obs"],
            [[t.from_state, t.to_state, t.trigger, t.observation_count]
             for t in result.transitions],
        )

    # -- inferred activities ----------------------------------------------
    if result.segments:
        lines += ["## Inferred activities", "",
                  "The session, split into probable business activities from idle "
                  "gaps, form submissions and route structure. This is an "
                  "**interpretation** of the timeline, not a rewrite of it: the "
                  "ordered workflow above is intact, and each activity cites the "
                  "raw events behind it. `confidence` reflects how intentional the "
                  "boundary evidence was.", ""]
        lines += _table(
            ["#", "Activity", "Actions", "Began", "Ended", "Conf"],
            [[s.index, s.label, s.action_count, s.boundary_reason, s.outcome,
              f"{s.confidence:.2f}"] for s in result.segments],
        )

    # -- capture health ----------------------------------------------------
    if result.health:
        health = result.health
        # A sanitised result carries `overall_code` and per-sensor counts
        # instead of the prose `overall` and `reasons`, because those are
        # derived strings rather than fixed constants. This renders either,
        # so one function serves both the local report and the shared one.
        overall = health.get("overall") or health.get("overall_code", "unknown")
        lines += ["## Capture health", "",
                  f"**{overall}**", "",
                  "Whether the application did nothing, or ScriptScrap failed to "
                  "see it. Statuses are categories; a percentage appears only "
                  "where a real denominator exists.", ""]
        lines += _table(
            ["Sensor", "Status", "Why"],
            [[s_.get("sensor", "-"), s_.get("status", "-"), _why(s_)]
             for s_ in health.get("sensors", [])],
        )
        if health.get("notes"):
            lines += ["### Notes", ""]
            lines += [f"- {n}" for n in health["notes"]] + [""]
        elif health.get("notes_count"):
            lines += ["### Notes", "",
                      f"_{health['notes_count']} note(s); the text is not in a "
                      "sanitised export._", ""]

    # -- forensic scripts --------------------------------------------------
    if result.scripts:
        lines += ["## Captured scripts", "",
                  "Source text stays in the local blob store; this is an "
                  "inventory of what each file declares.", ""]
        lines += _table(
            ["Script", "sha256", "Size", "Declared functions", "Network APIs"],
            [[f"`{(s_.get('url') or '')[-48:]}`", (s_.get("sha256") or "")[:12],
              s_.get("size"), len((s_.get("inventory") or {}).get("declared_functions", [])),
              ", ".join((s_.get("inventory") or {}).get("network_apis", [])) or "-"]
             for s_ in result.scripts],
        )

    # -- findings ----------------------------------------------------------
    lines += ["## Capture gaps and caveats", "",
              "What the tool knows it did **not** see. Absence here is the "
              "difference between 'the application did nothing' and 'ScriptScrap "
              "could not observe it'.", ""]
    lines += _table(
        ["Severity", "Kind", "Detail", "Count"],
        [[f.severity, f.kind, f.message, f.count] for f in result.findings],
    )

    return "\n".join(lines).rstrip() + "\n"
