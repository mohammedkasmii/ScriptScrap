"""Content-addressed blob store for large raw evidence.

Response bodies dominate the size of a forensic session and repeat heavily: the
same JS bundle across forty navigations is one blob, not forty. Addressing by
SHA-256 gives deduplication for free, and turns "did this response change?" into
a hash comparison, which is what session-to-session comparison will need.

Events keep only metadata:

    body: {sha256, size, media_type, storage}

Properties this guarantees:

* **Immutable.** A blob is named by its content, so writing it twice is a no-op
  and a blob can never be silently modified in place.
* **Atomic.** Written to a temporary file and renamed, so a crash mid-write
  cannot leave a truncated blob under a hash that claims to describe it.
* **Bounded.** The caller supplies a size limit; over-limit bodies are recorded
  as skipped WITH A REASON rather than silently dropped.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_MAX_BLOB_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class BlobRef:
    """What an event records about a stored body."""

    sha256: str
    size: int
    media_type: str | None
    storage: str
    deduplicated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "storage": self.storage,
            "deduplicated": self.deduplicated,
        }


@dataclass(slots=True)
class BlobSkipped:
    """Why a body was deliberately not stored. Never a silent omission."""

    reason: str
    size: int
    media_type: str | None
    limit: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "skipped",
            "reason": self.reason,
            "size": self.size,
            "media_type": self.media_type,
            "limit": self.limit,
        }


class BlobStore:
    """SHA-256 addressed store under `<session>/blobs/`."""

    def __init__(self, root: str | Path, *, max_bytes: int = DEFAULT_MAX_BLOB_BYTES) -> None:
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.root.mkdir(parents=True, exist_ok=True)
        self.written = 0
        self.deduplicated = 0
        self.skipped = 0
        self.bytes_written = 0

    def path_for(self, digest: str) -> Path:
        """Two-level fan-out keeps any one directory from holding every blob."""
        return self.root / digest[:2] / digest[2:4] / digest

    def put(
        self, data: bytes, *, media_type: str | None = None
    ) -> BlobRef | BlobSkipped:
        """Store bytes, or explain why not."""
        size = len(data)
        if size > self.max_bytes:
            self.skipped += 1
            return BlobSkipped(
                reason="configured_size_limit", size=size,
                media_type=media_type, limit=self.max_bytes,
            )

        digest = hashlib.sha256(data).hexdigest()
        target = self.path_for(digest)
        relative = target.relative_to(self.root.parent).as_posix()

        if target.exists():
            self.deduplicated += 1
            return BlobRef(digest, size, media_type, relative, deduplicated=True)

        target.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename: a crash cannot leave a partial file under a hash
        # that asserts what it contains.
        handle, temp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
        try:
            with os.fdopen(handle, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            Path(temp_name).replace(target)
        except OSError:
            Path(temp_name).unlink(missing_ok=True)
            raise

        self.written += 1
        self.bytes_written += size
        return BlobRef(digest, size, media_type, relative)

    def get(self, digest: str) -> bytes | None:
        path = self.path_for(digest)
        return path.read_bytes() if path.exists() else None

    def exists(self, digest: str) -> bool:
        return self.path_for(digest).exists()

    def count(self) -> int:
        return sum(1 for p in self.root.rglob("*") if p.is_file())

    def stats(self) -> dict[str, Any]:
        return {
            "blobs_written": self.written,
            "deduplicated": self.deduplicated,
            "skipped": self.skipped,
            "bytes_written": self.bytes_written,
            "max_bytes": self.max_bytes,
        }
