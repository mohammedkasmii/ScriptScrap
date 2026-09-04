"""GraphQL recognition. Pure functions, no browser."""

from __future__ import annotations

from scriptscrap.sensors import describe_graphql, looks_like_graphql, operation_label


def test_named_query_keeps_its_identity():
    body = {"operationName": "GetItem", "query": "query GetItem($id: ID!) { item(id: $id) { name } }",
            "variables": {"id": "7"}}
    d = describe_graphql("https://h/graphql", body)
    op = d["operations"][0]
    assert op["operation_name"] == "GetItem"
    assert op["operation_type"] == "query"
    assert op["variable_names"] == ["id"]
    assert operation_label(d) == "query GetItem"


def test_mutation_name_recovered_from_the_document():
    body = {"query": "mutation SaveItem($in: Input!) { saveItem(input: $in) { id } }"}
    op = describe_graphql("https://h/graphql", body)["operations"][0]
    assert op["operation_type"] == "mutation"
    assert op["operation_name"] == "SaveItem"


def test_anonymous_shorthand_is_a_query():
    op = describe_graphql("https://h/graphql", {"query": "{ viewer { id } }"})["operations"][0]
    assert op["operation_type"] == "query"
    assert op["operation_name"] is None
    assert op["document_hash"]


def test_leading_comments_do_not_defeat_detection():
    body = {"query": "# generated\n# do not edit\nquery Ping { ping }"}
    op = describe_graphql("https://h/graphql", body)["operations"][0]
    assert op["operation_type"] == "query"
    assert op["operation_name"] == "Ping"


def test_document_hash_is_whitespace_stable():
    a = describe_graphql("https://h/graphql", {"query": "query A { x }"})["operations"][0]
    b = describe_graphql("https://h/graphql", {"query": "query   A {\n  x\n}"})["operations"][0]
    assert a["document_hash"] == b["document_hash"]


def test_persisted_query_records_the_hash_and_the_missing_document():
    body = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "abc123"}}}
    op = describe_graphql("https://h/graphql", body)["operations"][0]
    assert op["persisted_query_hash"] == "abc123"
    assert op["document_present"] is False
    assert "never sent over the wire" in op["note"]


def test_batched_operations_are_all_described():
    body = [
        {"operationName": "A", "query": "query A { a }"},
        {"operationName": "B", "query": "mutation B { b }"},
    ]
    d = describe_graphql("https://h/graphql", body)
    assert d["batched"] is True
    assert d["operation_count"] == 2
    assert [o["operation_name"] for o in d["operations"]] == ["A", "B"]
    assert "+1 more" in operation_label(d)


def test_graphql_detected_by_body_even_on_an_unrelated_url():
    assert looks_like_graphql("https://h/api/v2/gateway", {"query": "query A { a }"})
    d = describe_graphql("https://h/api/v2/gateway", {"query": "query A { a }"})
    assert d["operations"][0]["operation_name"] == "A"


def test_plain_rest_is_not_graphql():
    assert describe_graphql("https://h/api/items", {"id": 1, "name": "x"}) is None
    assert describe_graphql("https://h/api/items", None) is None
    assert not looks_like_graphql("https://h/api/items", {"id": 1})


def test_graphql_url_with_unreadable_body_is_still_marked():
    d = describe_graphql("https://h/graphql", "raw-unparsed-string")
    assert d is not None
    assert d["operation_count"] == 0
    assert "unparsed" in d["note"]


def test_never_raises_on_hostile_input():
    for body in [{"query": 123}, {"query": None}, {"variables": "not-a-dict"}, [], [1, 2, 3]]:
        describe_graphql("https://h/graphql", body)
