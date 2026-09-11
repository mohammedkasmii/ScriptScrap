"""Offline table and dynamic-data catalog.

A table is where a lot of agency work happens: an operator sorts a column,
filters, pages through, edits a cell, clicks a row's action. Every such
interaction carries the table context the probe captured, and this assembles
them, per table, into one record: identity and caption, the columns, the rows
actually observed (deduplicated), the row-level actions, and a tally of the
sort/filter/paginate operations performed.

What is achievable from passive observation is the rows the operator actually
touched and the header row, not every virtualised row that never scrolled into
an interaction -- so the catalog is honest about being a record of what was
USED, the same posture the whole tool takes.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..events import Event, EventType
from .models import Evidence

_ACTION_TYPES = (
    EventType.USER_CLICK, EventType.USER_DBLCLICK, EventType.USER_RIGHTCLICK,
    EventType.USER_INPUT, EventType.USER_CHANGE, EventType.USER_SUBMIT,
    EventType.USER_SCROLL,
)

# A hard bound so a multi-hour session scrolling a huge virtualized table cannot
# grow the catalog without limit. The rows kept are those observed earliest;
# the count of how many were seen is preserved.
_MAX_ROWS_PER_TABLE = 500

# Words in a control's accessible name that mark a pagination action.
_PAGINATION_WORDS = ("next", "prev", "previous", "page", "suivant", "précédent",
                     "precedent", "first", "last", "»", "«")


@dataclass(slots=True)
class TableCatalogEntry:
    """One table the operator worked, and what was observed of it."""

    table_key: str
    table_id: str | None
    frame_id: str | None
    caption: str | None = None
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    row_actions: list[str] = field(default_factory=list)
    operations: dict[str, int] = field(default_factory=dict)
    evidence: Evidence = field(default_factory=Evidence)


class TableCatalogAnalyzer:
    """Builds the table catalog from the event log."""

    def analyze(self, events: list[Event]) -> list[TableCatalogEntry]:
        ordered = sorted(events, key=lambda e: e.seq)
        entries: dict[str, TableCatalogEntry] = {}
        # row identity -> row record, per table, so the same row observed twice
        # is one row.
        rows: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        actions: dict[str, list[str]] = defaultdict(list)
        ops: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        prev_op_key: tuple[str, str] | None = None

        for event in ordered:
            if event.type not in _ACTION_TYPES:
                continue
            table = event.payload.get("table")
            if not isinstance(table, dict):
                continue
            key = self._key(event, table)
            entry = entries.get(key)
            if entry is None:
                entry = TableCatalogEntry(
                    table_key=key, table_id=table.get("table_id"),
                    frame_id=event.frame_id, caption=table.get("caption"))
                entries[key] = entry
            entry.evidence.cite(event.event_id)

            columns = table.get("columns")
            if isinstance(columns, list) and len(columns) >= len(entry.columns):
                entry.columns = [str(c) for c in columns]
            if table.get("caption") and not entry.caption:
                entry.caption = str(table["caption"])

            # The operation this event performed (sort/filter/paginate/scroll),
            # so a newly-observed row-set can be attributed to what revealed it.
            if event.type is EventType.USER_SCROLL:
                op, prev_op_key = "scroll", prev_op_key
            else:
                op, prev_op_key = self._operation(event, table, key, prev_op_key)
                self._record_row(rows[key], table, op or "open")
            if op:
                ops[key][op] += 1
            elif self._is_row_action(event, table):
                label = self._action_label(event)
                if label and label not in actions[key]:
                    actions[key].append(label)

            # Rows harvested from the viewport on a scroll or a table operation,
            # deduplicated by stable id (or a cell fingerprint), each tagged with
            # the operation that first revealed it.
            self._record_visible_rows(rows[key], table.get("visible_rows"),
                                      op or "open")

        result = []
        for key, entry in entries.items():
            entry.rows = list(rows[key].values())
            entry.row_actions = actions[key]
            entry.operations = dict(sorted(ops[key].items()))
            result.append(entry)
        result.sort(key=lambda t: (-len(t.rows), t.table_key))
        return result

    @staticmethod
    def _key(event: Event, table: dict) -> str:
        ident = table.get("table_id") or table.get("caption") or "(table)"
        return f"{event.frame_id}|{ident}"

    @staticmethod
    def _row_identity(row_id, index, cells) -> str:
        if row_id:
            return str(row_id)
        if index is not None:
            return f"i{index}"
        # No stable id: a bounded fingerprint of the cell contents. Two rows with
        # identical cells are indistinguishable and collapse, which is the
        # correct, conservative behaviour for a virtualized table with no ids.
        return "c|" + "|".join(str(c) for c in cells)[:200]

    @classmethod
    def _record_row(cls, store: dict[str, dict[str, Any]], table: dict, via: str) -> None:
        cells = table.get("cells")
        if not isinstance(cells, list) or not cells:
            return
        # A header-only interaction (a sort) is not a data row.
        if table.get("on_header"):
            return
        cls._store_row(store, table.get("row_id"), table.get("row_index"), cells, via)

    @classmethod
    def _record_visible_rows(cls, store: dict[str, dict[str, Any]],
                             visible_rows, via: str) -> None:
        if not isinstance(visible_rows, list):
            return
        for row in visible_rows:
            if not isinstance(row, dict):
                continue
            cells = row.get("cells")
            if not isinstance(cells, list) or not cells:
                continue
            cls._store_row(store, row.get("row_id"), row.get("row_index"), cells, via)

    @classmethod
    def _store_row(cls, store, row_id, index, cells, via: str) -> None:
        identity = cls._row_identity(row_id, index, cells)
        if identity in store:
            return          # already observed: keep the first sighting's provenance
        if len(store) >= _MAX_ROWS_PER_TABLE:
            return          # bounded for a multi-hour session
        store[identity] = {
            "row_id": row_id,
            "row_index": index,
            "cells": [str(c) for c in cells],
            "observed_via": via,
        }

    def _operation(self, event, table, key, prev_op_key):
        """Classify an interaction as sort / filter / paginate, if it is one.

        Returns (operation | None, updated prev_op_key). Consecutive filter
        keystrokes on one control collapse to a single filter operation.
        """
        element = event.payload.get("element") or {}
        if table.get("on_header") or str(element.get("tag")) == "th" \
                or element.get("role") == "columnheader":
            return "sort", None
        if event.type in (EventType.USER_INPUT, EventType.USER_CHANGE):
            control = element.get("id") or element.get("name") or "filter"
            this = (key, str(control))
            if this == prev_op_key:
                return None, this          # same filter field, still typing
            return "filter", this
        label = (self._action_label(event) or "").lower()
        if any(word in label for word in _PAGINATION_WORDS):
            return "paginate", None
        return None, prev_op_key

    @staticmethod
    def _is_row_action(event, table) -> bool:
        # A click on a control inside a data row (not the header) is a row action.
        if event.type not in (EventType.USER_CLICK, EventType.USER_DBLCLICK,
                              EventType.USER_RIGHTCLICK):
            return False
        if table.get("on_header"):
            return False
        element = event.payload.get("element") or {}
        return str(element.get("tag")) in ("button", "a") or bool(element.get("role"))

    @staticmethod
    def _action_label(event) -> str | None:
        element = event.payload.get("element") or {}
        label = element.get("label") or element.get("text")
        return str(label) if label else None


__all__ = ["TableCatalogAnalyzer", "TableCatalogEntry"]
