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
        out.append(f"| _… {len(rows) - MAX_ROWS} more_ |" + " |" * (len(headers) - 1))
    out.append("")
    return out


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
            ["Field", "Type", "Present", "Optional", "Format", "Enum candidate"],
            [[f"`{f.path}`", f.inferred_type, f"{f.present_count}/{f.sample_count}",
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
