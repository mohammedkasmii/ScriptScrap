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


# The regions of the dataset whose contract is that NO captured value appears
# in them, in any form. These are the 28 fields the audit found leaking.
#
# `endpoints`, `schemas` and `ui_elements[].locators` are deliberately not
# here: ROUTE keeps route words, NAME keeps field paths and parameter names,
# and LOCATOR keeps a structural `#id` selector. Each is a documented,
# load-bearing trade pinned by tests/test_export_policy.py --
# `test_the_documented_limits_of_route_and_name` and
# `test_a_route_word_is_kept_and_that_is_the_documented_trade`.
NEVER_VERBATIM_REGIONS = (
    "ui_elements", "findings", "capture_health", "transitions",
    "technologies", "dependencies", "states",
)


def _never_verbatim_blob(payload: dict) -> str:
    """The parts of the export that promise to carry no captured value.

    `ui_elements` is included but its `locators` are stripped first, so the
    documented locator trade does not mask the fields around it.
    """
    import copy

    regions = {}
    for name in NEVER_VERBATIM_REGIONS:
        region = copy.deepcopy(payload.get(name))
        if name == "ui_elements":
            for element in region or []:
                element.pop("locators", None)
                element.pop("recommended", None)
        regions[name] = region
    return json.dumps(regions, ensure_ascii=False)


def _collect_strings(value, into: set[str]) -> None:
    if isinstance(value, str):
        into.add(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            into.add(str(key))
            _collect_strings(item, into)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, into)


def test_shared_dataset_leaks_no_fixture_secret(tmp_path):
    """Not four planted strings: every interesting string the fixture log holds.

    The old version checked FIXTURE_SECRETS and passed while the export carried
    element text verbatim -- because the fixture never puts a secret in element
    text and the real capture did.
    """
    from scriptscrap.events import EventLogReader

    result = analyze_log(SAMPLE_EVENT_LOG)
    exporter = DatasetExporter()
    path = exporter.write(result, tmp_path / "shared")
    blob = path.read_text(encoding="utf-8")

    for secret in FIXTURE_SECRETS:
        assert secret not in blob, f"{secret} leaked into the shareable export"
    assert "Bearer " not in blob
    assert "eyJ" not in blob
    assert "Alice Benali" not in blob, "operator-typed PII leaked into the export"

    captured: set[str] = set()
    for event in EventLogReader(SAMPLE_EVENT_LOG):
        _collect_strings(event.payload, captured)

    # A captured string long enough to be a value, and carrying a space or a
    # digit so it is not a bare vocabulary word.
    interesting = {
        s for s in captured
        if len(s) >= 8 and any(ch.isspace() or ch.isdigit() for ch in s)
    }
    region = _never_verbatim_blob(exporter.build(result))
    survivors = sorted(s for s in interesting if s in region)
    assert survivors == [], (
        f"{len(survivors)} captured string(s) reached a never-verbatim region: "
        f"{survivors[:5]}")


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
