"""The shareable export must be safe, and still useful.

Safe is the easy half. The harder property is that redaction must not destroy
the value-propagation signal: replacing every secret with `***` would make the
shared dataset show no dependencies at all. Deterministic pseudonyms keep the
relationships visible while removing the values.
"""

from __future__ import annotations

import json

from golden_support import SAMPLE_EVENT_LOG

from scriptscrap.analysis import analyze_log
from scriptscrap.export import DatasetExporter, Pseudonymizer, Redactor, is_credential_name

# Values the fixture plants so leak detection has something to trip on.
FIXTURE_SECRETS = (
    "FIXTURE_PASSWORD_DO_NOT_USE",
    "FIXTURE_CSRF_TOKEN_0001",
    "FIXTURE_SESSION_TOKEN_0001",
    "fixture@example.test",
)


def test_credential_names_are_recognised():
    for name in ("Authorization", "Cookie", "X-CSRF-Token",
                 "__RequestVerificationToken", "pw", "password", "sessionId"):
        assert is_credential_name(name), name
    for name in ("Content-Type", "Accept", "page", "missionId", "reference"):
        assert not is_credential_name(name), name


def test_credential_values_are_removed_not_pseudonymised():
    r = Redactor()
    out = r.scrub({"authorization": "Bearer abcdefghijklmnop", "page": 2})
    assert "abcdefghijklmnop" not in json.dumps(out)
    assert out["authorization"].startswith("<redacted")
    assert out["page"] == 2


def test_jwt_and_private_key_are_removed_wherever_they_appear():
    r = Redactor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlZGF0YQ"
    assert jwt not in r.scrub_text(f"token is {jwt} ok")
    assert "private key" in r.scrub_text("-----BEGIN RSA PRIVATE KEY-----")


def test_pseudonyms_are_deterministic_so_correlation_survives():
    """The point of pseudonymising rather than deleting."""
    r = Redactor()
    first = r.scrub_text("ITEMREF-AA0101")
    second = r.scrub_text("ITEMREF-AA0101")
    other = r.scrub_text("ITEMREF-BB0102")
    assert first == second, "the same value must map to the same pseudonym"
    assert first != other, "different values must map to different pseudonyms"
    assert "ITEMREF" not in first


def test_emails_are_pseudonymised_consistently():
    r = Redactor()
    text = r.scrub_text("contact fixture@example.test or fixture@example.test")
    assert "fixture@example.test" not in text
    assert text.count("EMAIL_001") == 2


def test_value_preview_is_always_pseudonymised():
    """It sits on every dependency edge and always carries a captured value."""
    r = Redactor()
    out = r.scrub({"value_preview": "FIXTURE_CSRF_TOKEN_0001",
                   "ordering_method": "same_source_seq"})
    assert "FIXTURE_CSRF_TOKEN_0001" not in json.dumps(out)
    assert out["ordering_method"] == "same_source_seq", "vocabulary must survive"


def test_underscore_separated_tokens_are_pseudonymised():
    r = Redactor()
    assert "FIXTURE_CSRF_TOKEN_0001" not in r.scrub_text("FIXTURE_CSRF_TOKEN_0001")
    assert "FIXTURE_SESSION_TOKEN_0001" not in r.scrub_text("FIXTURE_SESSION_TOKEN_0001")


def test_vocabulary_is_not_mistaken_for_data():
    """Analysis vocabulary must survive: pseudonymising it would corrupt the dataset."""
    r = Redactor()
    for word in ("same_source_seq", "response_to_request", "wall_clock",
                 "user_input_to_request", "probe_ordinal"):
        assert r.scrub_text(word) == word, f"{word} was wrongly treated as data"


def test_free_text_examples_are_pseudonymised_but_vocabulary_survives():
    """A typed name is data; a status code is vocabulary."""
    r = Redactor()
    assert r.scrub_example("Alice Benali") != "Alice Benali", "operator-typed PII leaked"
    assert r.scrub_example("Item cent deux") != "Item cent deux"
    assert r.scrub_example("GAR-0007") != "GAR-0007", "an identifier leaked"
    # Keeping these is what makes `statut in {OK, ARCHIVE}` useful downstream.
    assert r.scrub_example("OK") == "OK"
    assert r.scrub_example("ARCHIVE") == "ARCHIVE"
    assert r.scrub_example(42) == 42
    assert r.scrub_example(True) is True


def test_pseudonymizer_is_stable_within_a_session():
    p = Pseudonymizer(salt="s")
    assert p.pseudonym("A", "ID") == p.pseudonym("A", "ID")
    assert p.pseudonym("B", "ID") != p.pseudonym("A", "ID")


def test_shared_dataset_leaks_no_fixture_secret(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    exporter = DatasetExporter()
    path = exporter.write(result, tmp_path / "shared")
    blob = path.read_text(encoding="utf-8")

    for secret in FIXTURE_SECRETS:
        assert secret not in blob, f"{secret} leaked into the shareable export"
    assert "Bearer " not in blob
    assert "eyJ" not in blob
    # Operator-typed personal data is neither credential- nor identifier-shaped,
    # so it needs its own rule; an earlier version of the exporter leaked it.
    assert "Alice Benali" not in blob, "operator-typed PII leaked into the export"


def test_shared_dataset_excludes_raw_artifacts(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    payload = DatasetExporter().build(result)
    assert "screenshots" not in payload
    assert "html_snapshots" not in payload
    blob = json.dumps(payload)
    assert "<!DOCTYPE" not in blob and "<html" not in blob, "raw HTML reached the export"


def test_shared_dataset_keeps_the_analysis_useful(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    payload = DatasetExporter().build(result)
    assert payload["endpoints"], "an export with no endpoints is not useful"
    assert payload["schemas"]
    assert payload["findings"], "capture gaps must survive into the shared dataset"
    for dependency in payload["dependencies"]:
        assert dependency["evidence_ids"], "evidence links must survive redaction"
        assert "confidence" in dependency


def test_export_reports_what_it_did(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    exporter = DatasetExporter()
    exporter.write(result, tmp_path / "shared")
    stats = exporter.redactor.stats()
    assert set(stats) == {"credentials_removed", "values_pseudonymised",
                          "distinct_pseudonyms"}

# --- real-world capture regression --------------------------------------

def test_bare_csrf_field_name_is_a_credential():
    """A live login form named its token field `_csrf`.

    The name list spelled out `x-csrf-token` and `csrf-token` but not the bare
    stem, so the field sailed through into a generated OpenAPI example.
    """
    from scriptscrap.export.redact import is_credential_name

    for name in ("_csrf", "csrf", "csrfToken", "_xsrf", "XSRF-TOKEN"):
        assert is_credential_name(name), name


def test_ordinary_field_names_are_not_credentials():
    """The stem must not start swallowing vocabulary."""
    from scriptscrap.export.redact import is_credential_name

    for name in ("id", "name", "status", "same_source_seq", "response_to_request",
                 "url", "method", "count"):
        assert not is_credential_name(name), name
