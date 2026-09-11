"""Offline table and dynamic-data catalog.

When an employee works a table -- sorts a column, filters, pages, edits a cell,
clicks a row's action -- each interaction carries the table it happened in. This
assembles those into one catalog per table: its identity and caption, the
columns, the rows actually observed, the row-level actions, and a tally of the
sort/filter/paginate operations the operator performed on it.

Synthetic events, so a test states exactly what was observed.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis import analyze_events
from scriptscrap.analysis.tables import TableCatalogAnalyzer
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def _reset():
    global _seq
    _seq = itertools.count(1)


def ev(etype, element, table=None, **payload):
    n = next(_seq)
    body = {"element": element, **payload}
    if table is not None:
        body["table"] = table
    return Event(session_id="s", event_id=f"evt-{n:08d}", seq=n,
                 t_wall=f"2026-01-01T00:00:{n % 60:02d}+00:00", t_mono=float(n),
                 source=Source.RUNTIME, type=etype, payload=body,
                 page_id="p1", frame_id="f1")


def row_action(label, row_index, cells, table_id="orders"):
    return ev(EventType.USER_CLICK,
              {"tag": "button", "label": label, "id": f"act-{row_index}"},
              table={"table_id": table_id, "caption": "Orders",
                     "columns": ["Id", "Customer", "Total", ""],
                     "row_index": row_index, "cells": cells, "on_header": False})


def sort(column_index, table_id="orders"):
    return ev(EventType.USER_CLICK,
              {"tag": "th", "role": "columnheader", "label": "Customer"},
              table={"table_id": table_id, "columns": ["Id", "Customer", "Total", ""],
                     "row_index": 0, "cells": ["Customer"], "on_header": True})


def filter_input(text, table_id="orders"):
    return ev(EventType.USER_INPUT,
              {"tag": "input", "type": "search", "id": "table-filter",
               "placeholder": "Filter orders"},
              table={"table_id": table_id, "columns": ["Id", "Customer", "Total", ""]},
              value={"value": text})


def _catalog(events):
    return TableCatalogAnalyzer().analyze(events)


def test_an_empty_session_has_no_tables():
    _reset()
    assert _catalog([]) == []


def test_a_table_records_its_identity_columns_and_caption():
    _reset()
    tables = _catalog([row_action("Edit", 0, ["1", "Alice", "42", ""])])
    assert len(tables) == 1
    table = tables[0]
    assert table.table_id == "orders"
    assert table.caption == "Orders"
    assert table.columns == ["Id", "Customer", "Total", ""]


def test_observed_rows_are_collected_and_deduplicated():
    _reset()
    tables = _catalog([
        row_action("Edit", 0, ["1", "Alice", "42", ""]),
        row_action("Edit", 1, ["2", "Bob", "17", ""]),
        row_action("Delete", 0, ["1", "Alice", "42", ""]),   # same row again
    ])
    rows = tables[0].rows
    assert len(rows) == 2, "the same row observed twice must be one row"
    assert any(r["cells"][1] == "Alice" for r in rows)


def test_row_actions_are_recorded():
    _reset()
    tables = _catalog([
        row_action("Edit", 0, ["1", "Alice", "42", ""]),
        row_action("Delete", 1, ["2", "Bob", "17", ""]),
    ])
    assert {"Edit", "Delete"} <= set(tables[0].row_actions)


def test_sort_and_filter_operations_are_tallied():
    _reset()
    tables = _catalog([
        sort(1),
        filter_input("ali"),
        filter_input("alice"),   # consecutive typing is one filter operation
    ])
    ops = tables[0].operations
    assert ops.get("sort", 0) >= 1
    assert ops.get("filter", 0) >= 1


def test_tables_are_exposed_on_the_analysis_result():
    _reset()
    result = analyze_events([row_action("Edit", 0, ["1", "Alice", "42", ""])], "s")
    assert result.tables
    assert result.tables[0].table_id == "orders"


def test_every_table_cites_its_evidence():
    _reset()
    tables = _catalog([row_action("Edit", 0, ["1", "Alice", "42", ""])])
    assert tables[0].evidence.event_ids
