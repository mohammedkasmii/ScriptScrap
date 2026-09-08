"""Offline analysis over the raw event spine.

    events.jsonl  ->  analysis  ->  session.sqlite + report

HARD BOUNDARY: nothing in this package may import Playwright, Camoufox, or
`scriptscrap.sensors`. Analysis reads recorded evidence, so it must run on a
machine with no browser -- which is also what makes it testable without one.
`tests/test_analysis_boundary.py` enforces this.

Everything produced here is DERIVED KNOWLEDGE: an inference carrying the
`event_id`s that justify it, never written back into a raw event.
"""

from .correlation import CorrelationAnalyzer, field_name_similarity, normalize_field_tokens
from .endpoints import EndpointAnalyzer
from .models import (
    ANALYSIS_VERSION,
    AnalysisResult,
    AppState,
    DependencyEdge,
    Endpoint,
    Evidence,
    Finding,
    LocatorCandidate,
    ParamObservation,
    Schema,
    SchemaField,
    StateTransition,
    Technology,
    UIElement,
)
from .pipeline import analyze_events, analyze_log
from .schema import SchemaInferrer
from .selectors import SelectorAnalyzer, generated_id_warning, semantic_key
from .states import StateAnalyzer, route_shape
from .store import DerivedStore
from .technology import TechnologyAnalyzer

__all__ = [
    "ANALYSIS_VERSION",
    "AnalysisResult",
    "AppState",
    "CorrelationAnalyzer",
    "DependencyEdge",
    "DerivedStore",
    "Endpoint",
    "EndpointAnalyzer",
    "Evidence",
    "Finding",
    "LocatorCandidate",
    "ParamObservation",
    "Schema",
    "SchemaField",
    "SchemaInferrer",
    "SelectorAnalyzer",
    "StateAnalyzer",
    "StateTransition",
    "Technology",
    "TechnologyAnalyzer",
    "UIElement",
    "analyze_events",
    "analyze_log",
    "field_name_similarity",
    "generated_id_warning",
    "normalize_field_tokens",
    "route_shape",
    "semantic_key",
]
