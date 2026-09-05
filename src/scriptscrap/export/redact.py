"""Redaction for the shareable export.

Two-tier model, from the evolution blueprint:

    raw vault        events.jsonl + artifacts. Unredacted, local, gitignored.
    shared export    safe by default. Credentials removed, identifiers
                     pseudonymised, documents reduced to metadata.

The design decision that makes this useful rather than merely safe:
**pseudonymisation is deterministic**. Naive redaction replaces every secret
with `***`, which destroys exactly the value-propagation signal the dependency
analysis depends on -- a shared dataset would show no dependencies at all. Here
the same input always maps to the same pseudonym within a session, so
`ITEMREF-AA0101` appearing in a response and again in a later request still
appears as one repeated value, and the edge survives.

Credentials are handled differently from identifiers: they are REMOVED and
replaced by a description of their shape, because a stable pseudonym for a
password would still leak its length and reuse pattern.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Header and field names whose values authenticate a session.
CREDENTIAL_NAMES = frozenset({
    "authorization", "proxy-authorization", "www-authenticate", "authentication",
    "cookie", "set-cookie", "cookie2",
    "x-csrf-token", "csrf-token", "x-csrftoken", "x-xsrf-token", "xsrf-token",
    "x-requestverificationtoken", "__requestverificationtoken",
    "x-api-key", "api-key", "apikey", "x-apikey",
    "x-auth-token", "auth-token", "x-access-token", "access-token",
    "x-session-id", "x-session-token", "session-id", "sessionid",
    "pw", "pwd", "passwd", "pass", "password", "motdepasse",
})
CREDENTIAL_SUBSTRINGS = (
    "auth", "token", "secret", "credential", "session", "cookie",
    "apikey", "api-key", "password", "signature", "assertion",
    # A real capture's login form named its CSRF field `_csrf`, which matched
    # none of the fully-spelled names above. The bare stem is what actually
    # appears in the wild.
    "csrf", "xsrf",
)

# Value shapes that are credentials wherever they appear.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*", re.I)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Identifier-shaped values worth pseudonymising rather than deleting. The tail
# admits underscores as well as hyphens: FIXTURE_CSRF_TOKEN_0001 is exactly the
# shape that must not survive, and an earlier version of this pattern let it
# through because it only allowed hyphens after the first separator.
#
# A separator alone is not enough: `same_source_seq` and `response_to_request`
# are vocabulary, not data, and pseudonymising them would corrupt the very
# signals the shared dataset exists to convey. An identifier must also carry a
# digit, which is what distinguishes ITEMREF-AA0101 and FIXTURE_CSRF_TOKEN_0001
# from an ordinary snake_case word.
_IDENTIFIER = re.compile(r"^(?=.*\d)[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9_-]{3,}$")

# Keys whose value IS a captured value by definition, whatever they are named.
# `value_preview` sits on every dependency edge to show what propagated, so it
# always carries real data and must never be passed through untouched.
ALWAYS_PSEUDONYMISE_KEYS = frozenset({
    "value_preview", "value", "example", "examples", "sample", "samples",
})


def is_credential_name(name: str) -> bool:
    lowered = str(name).lower().lstrip(":")
    if lowered in CREDENTIAL_NAMES:
        return True
    return any(marker in lowered for marker in CREDENTIAL_SUBSTRINGS)


def describe_credential(value: Any) -> str:
    """A shape description, so the reader knows what to supply without the value."""
    text = "" if value is None else str(value)
    if _JWT.search(text):
        return "<redacted: JWT, 3 segments>"
    if _BEARER.search(text):
        return "<redacted: Bearer token>"
    if _PRIVATE_KEY.search(text):
        return "<redacted: private key>"
    return f"<redacted: credential, {len(text)} chars>"


class Pseudonymizer:
    """Stable fake values for real ones, consistent within one export.

    The mapping is derived from a per-export salt, so the same session exported
    twice produces the same pseudonyms, and two different sessions do not leak
    that they share a value.
    """

    def __init__(self, salt: str = "") -> None:
        self.salt = salt
        self._assigned: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def pseudonym(self, value: str, kind: str = "ID") -> str:
        existing = self._assigned.get(value)
        if existing:
            return existing
        self._counters[kind] = self._counters.get(kind, 0) + 1
        assigned = f"{kind}_{self._counters[kind]:03d}"
        self._assigned[value] = assigned
        return assigned

    def fingerprint(self, value: str) -> str:
        digest = hashlib.sha256((self.salt + value).encode("utf-8", "ignore")).hexdigest()
        return digest[:12]

    @property
    def mapping_size(self) -> int:
        return len(self._assigned)


class Redactor:
    """Applies the credential and identifier policy to arbitrary structures."""

    def __init__(self, pseudonymizer: Pseudonymizer | None = None) -> None:
        self.pseudonyms = pseudonymizer or Pseudonymizer()
        self.credentials_removed = 0
        self.values_pseudonymised = 0

    def scrub(self, value: Any, name: str | None = None, depth: int = 0) -> Any:
        """Redact recursively. `name` is the key this value arrived under."""
        if depth > 12:
            return value

        if name and is_credential_name(name) and value is not None:
            self.credentials_removed += 1
            return describe_credential(value)

        if name in ALWAYS_PSEUDONYMISE_KEYS and isinstance(value, str) and value:
            return self._pseudonym(value, "VALUE")

        if isinstance(value, dict):
            return {k: self.scrub(v, name=str(k), depth=depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v, name=name, depth=depth + 1) for v in value]
        if isinstance(value, str):
            return self.scrub_text(value)
        return value

    def scrub_text(self, text: str) -> str:
        """Redact credential-shaped and pseudonymise identifier-shaped values."""
        if _PRIVATE_KEY.search(text):
            self.credentials_removed += 1
            return "<redacted: private key>"

        replaced = _JWT.sub(lambda _: self._removed("JWT"), text)
        replaced = _BEARER.sub(lambda _: self._removed("Bearer token"), replaced)
        replaced = _EMAIL.sub(
            lambda m: self._pseudonym(m.group(0), "EMAIL"), replaced)

        if replaced == text and _IDENTIFIER.match(text.strip()):
            return self._pseudonym(text.strip(), "ID")
        return replaced

    def scrub_example(self, value: Any) -> Any:
        """Redact a captured sample value.

        Examples and enum candidates are captured data, so the default is to
        pseudonymise. The exception is a short, single-token, digit-free string:
        that is vocabulary, not data. Keeping it means a shared dataset can still
        say `statut in {OK, ARCHIVE}`, which is the whole point of inferring an
        enum candidate -- while `Alice Benali` (whitespace) and `GAR-0007`
        (digits) are both replaced.
        """
        if not isinstance(value, str):
            return value                      # numbers and booleans are structural
        text = value.strip()
        if not text:
            return value

        scrubbed = self.scrub_text(text)
        if scrubbed != text:
            return scrubbed                   # already handled as credential/identifier

        is_vocabulary = (
            len(text) <= 24
            and not any(ch.isspace() for ch in text)
            and not any(ch.isdigit() for ch in text)
        )
        if is_vocabulary:
            return text
        return self._pseudonym(text, "VALUE")

    def _removed(self, label: str) -> str:
        self.credentials_removed += 1
        return f"<redacted: {label}>"

    def _pseudonym(self, value: str, kind: str) -> str:
        self.values_pseudonymised += 1
        return self.pseudonyms.pseudonym(value, kind)

    def stats(self) -> dict[str, int]:
        return {
            "credentials_removed": self.credentials_removed,
            "values_pseudonymised": self.values_pseudonymised,
            "distinct_pseudonyms": self.pseudonyms.mapping_size,
        }
