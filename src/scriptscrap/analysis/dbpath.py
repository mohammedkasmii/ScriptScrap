"""Opening a derived store read-only, on any legal path.

The store is opened read-only at the driver level rather than by convention,
which needs SQLite's URI syntax -- and a URI is not a path. A session directory
named `acme-#2` is legal on every platform this runs on, and pasting it into
`file:{path}?mode=ro` starts a URI fragment: SQLite opens something else and
then reports a missing table, which sends the reader to look at the schema.

`Path.as_uri()` is the encoder. It percent-encodes `#`, space, `%`, `$`, `'`,
`?` and `*`, produces `file:///C:/...` on Windows, and is stdlib.
"""

from __future__ import annotations

from pathlib import Path


def read_only_uri(path: str | Path) -> str:
    """A `file:` URI that opens `path` read-only.

    `mode=ro` also means a missing file is an error rather than a new empty
    database, which is what makes "no such table" impossible to reach by
    typo.
    """
    return Path(path).resolve().as_uri() + "?mode=ro"
