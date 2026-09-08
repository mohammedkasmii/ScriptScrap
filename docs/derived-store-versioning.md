# Versioning the derived store

Two numbers, two jobs. They move independently.

| Number | Where | Means | Consequence of a bump |
|---|---|---|---|
| `ANALYSIS_VERSION` | `src/scriptscrap/analysis/models.py` | The inference changed: a stored result is no longer what this code would derive. | Readers ignore runs at an older version; `analyze` writes a new run. |
| `STORE_SCHEMA_VERSION` | `src/scriptscrap/analysis/store.py` | The SQL changed: a table, column, index or constraint. | `DerivedStore` discards the file and recreates it. |

## The rule

1. SQL changed (a table, a column, an index, a constraint) → bump
   `STORE_SCHEMA_VERSION`.
2. What analysis derives changed — a new model field, a new finding kind, a
   changed inference — with no SQL change → bump `ANALYSIS_VERSION`.
3. Both changed → bump both.
4. Never reuse a number. Never renumber downwards.
5. Add a row to the history below in the same commit as the bump.
6. One bump per plan, taken in the **first** commit of that plan that changes
   derivation. A plan that adds a model in one commit and a finding over it in
   the next has changed derivation once, not twice.

## Every migration edge

`DerivedStore.__init__` reconciles the SQL shape; the readers
(`EventStore._latest_run`, `api._run_id`) reconcile the inference. They are
checked in that order, because a file whose SQL this code cannot read cannot be
queried for its `analysis_version` at all.

| # | On disk | This build | What happens |
|---|---|---|---|
| 1 | file absent | any | Create the schema, stamp `STORE_SCHEMA_VERSION`. `rebuilt` stays False. |
| 2 | file present, `user_version = 0`, **no tables** (a zero-byte file) | any | Same as 1. `_has_tables()` is False, so nothing is discarded. |
| 3 | file present, `user_version = 0`, **tables present** — every store written before this task | any | Discard and recreate. `rebuilt = True`; `analyze` prints that it rebuilt. |
| 4 | `user_version < STORE_SCHEMA_VERSION` | any | Discard and recreate. Same as 3. |
| 5 | `user_version == STORE_SCHEMA_VERSION` | any | Open as-is. No rebuild. |
| 6 | `user_version > STORE_SCHEMA_VERSION` | any | **Raise `StoreSchemaError`.** Never discarded: this code does not know what a newer build put there, and deleting another version's work is not its call. The operator deletes the file if they mean to. |
| 7 | any of 3–5, opened with `on_mismatch="raise"` | — | Raise `StoreSchemaError` naming `scriptscrap analyze --rebuild`, instead of discarding. For a caller that would rather stop. |
| 8 | SQL current, `analysis_runs` holds runs only at an **older** `ANALYSIS_VERSION` | any | No rebuild — the SQL is fine. The readers ignore those runs and raise a named error telling the reader to run `analyze`. `analyze` itself writes a new run at the current version, and `_prune` (`keep=1`) removes the old one. |
| 9 | SQL current, runs at a **newer** `ANALYSIS_VERSION` | any | The readers select `= ANALYSIS_VERSION`, so a newer run is ignored exactly as an older one is, and the error names the remedy. Nothing is deleted by a reader; only `analyze`'s prune deletes, and it prunes by `session_id` after writing its own run. |
| 10 | SQL newer **and** runs newer | any | Edge 6 wins: the schema check runs first and raises before any run is read. |
| 11 | SQL current, `analysis_runs` empty | any | The readers raise the same named error as edge 8. A store with no run is not a partial store; it is one `analyze` away from being complete. |

Two consequences worth stating, because they are easy to get wrong later:

- **A rebuild is never silent.** Edge 3 and 4 set `DerivedStore.rebuilt`, and
  `cmd_analyze` prints it. A store that vanished without a line of output would
  look like data loss.
- **A reader never rebuilds.** Only `analyze` writes. `EventStore` and the
  workspace API raise and name the remedy; they do not repair a store behind
  the operator's back while they are reading evidence out of it.

## Why rebuild rather than migrate

`session.sqlite` is derived from `events.jsonl` and nothing else — that is
asserted by the module docstring of `store.py` and by the golden master. An
`ALTER TABLE` path would be work to preserve data that is reproducible by
definition, and a second code path that has to stay correct forever. The cost
of a rebuild is one re-run of `analyze`, which is 0.3 s on a 9,255-event log.

A store written by a **newer** build is never discarded: this code does not know
what that build put there, and deleting another version's work is not its call.

## History

| Store schema | Analysis | Change | Landed in |
|---|---|---|---|
| 1 | 2 | `analysis_runs.log_size`, `analysis_runs.log_sha256`, the `events` table and its four indexes. | `97c58c9`, retroactively stamped by the store-versioning commit |
| 2 | 3 | `workflow_steps` and its index; `state_transitions.trigger_type`, `.trigger_element_key`, `.trigger_event_id`. Analysis bumps in the same release: the ordered action model, the public `semantic_key`, and the transition-to-element link. | the Plan C commits |
| 3 | 3 | `state_transitions.trigger` and `findings.message` become nullable. Both are free text the export policy drops, and the store now persists a sanitised model as well as a raw one. No analysis change, so `ANALYSIS_VERSION` stays at 3. | the SANITISED-mode commit |
