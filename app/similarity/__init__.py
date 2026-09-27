"""Fuzzy file similarity (TLSH) and cross-job rule correlation helpers."""

from app.similarity.correlator import (
    CorrelatedFinding,
    find_correlated_findings_async,
    make_rule_signature,
)
from app.similarity.hasher import (
    SimilarFile,
    compute_tlsh,
    find_similar_files_async,
)

__all__ = [
    "CorrelatedFinding",
    "SimilarFile",
    "compute_tlsh",
    "find_correlated_findings_async",
    "find_similar_files_async",
    "make_rule_signature",
]
