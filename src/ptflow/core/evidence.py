"""Stable evidence fields shared by reports, benchmark evaluation, and future verifiers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, cast

Confidence = Literal["verified", "probable", "lead"]

CONFIDENCE_ORDER: dict[Confidence, int] = {"lead": 0, "probable": 1, "verified": 2}

_CLASS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?:^|[-_ ])(?:cross[-_ ]site[-_ ]scripting|xss)(?:$|[-_ ])", re.IGNORECASE),
     "xss"),
    (re.compile(r"(?:^|[-_ ])(?:sql[-_ ]?injection|sqli)(?:$|[-_ ])", re.IGNORECASE),
     "sqli"),
    (re.compile(r"(?:^|[-_ ])ssrf(?:$|[-_ ])", re.IGNORECASE), "ssrf"),
    (re.compile(r"(?:^|[-_ ])xxe(?:$|[-_ ])", re.IGNORECASE), "xxe"),
    (re.compile(r"(?:^|[-_ ])(?:command[-_ ]injection|cmdi)(?:$|[-_ ])", re.IGNORECASE),
     "command-injection"),
    (re.compile(r"(?:^|[-_ ])ssti(?:$|[-_ ])", re.IGNORECASE), "ssti"),
    (re.compile(r"(?:^|[-_ ])(?:lfi|path[-_ ]traversal)(?:$|[-_ ])", re.IGNORECASE),
     "path-traversal"),
    (re.compile(r"(?:^|[-_ ])open[-_ ]redirect(?:$|[-_ ])", re.IGNORECASE),
     "open-redirect"),
    (re.compile(r"(?:^|[-_ ])cors(?:$|[-_ ])", re.IGNORECASE), "cors"),
    (re.compile(r"(?:^|[-_ ])crlf(?:$|[-_ ])", re.IGNORECASE), "crlf"),
    (re.compile(r"(?:^|[-_ ])(?:idor|bola)(?:$|[-_ ])", re.IGNORECASE), "idor"),
    (re.compile(r"(?:^|[-_ ])(?:cve|cwe)[-_ ]?\d", re.IGNORECASE), "cve"),
)
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_PROBABLE_SCORE = 0.75
_GENERIC_TYPES = frozenset({"dns", "file", "http", "network", "ssl", "tcp", "tls", "udp"})
_DETECTOR_BY_CATEGORY = {
    "cve": "search-vulns",
    "cve-verified": "search-vulns",
    "dast": "nuclei",
    "nuclei-scope": "nuclei",
    "sqli": "sqlmap",
    "takeover": "subjack",
    "xss": "dalfox",
}


@dataclass(frozen=True)
class FindingEvidence:
    """The minimum scanner-independent evidence contract exposed in ``report.json``."""

    finding_id: str
    class_name: str
    target: str | None
    request_ref: str | None
    confidence: Confidence
    detector: str
    verification_method: str | None
    evidence_refs: tuple[str, ...]
    control_evidence_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "class": self.class_name,
            "target": self.target,
            "request_ref": self.request_ref,
            "confidence": self.confidence,
            "detector": self.detector,
            "verification_method": self.verification_method,
            "evidence_refs": list(self.evidence_refs),
            "control_evidence_refs": list(self.control_evidence_refs),
        }


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.strip().casefold()).strip("-") or "unknown"


def _first_text(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return None


def _refs(value: Any) -> tuple[str, ...]:
    if value in (None, "", [], {}):
        return ()
    values = value if isinstance(value, list | tuple | set) else (value,)
    refs: list[str] = []
    for item in values:
        if isinstance(item, dict):
            path = item.get("path")
            if path:
                line = item.get("line")
                refs.append(f"{path}:{line}" if line is not None else str(path))
        elif str(item).strip():
            refs.append(str(item).strip())
    return tuple(dict.fromkeys(refs))


def normalize_class(category: str, record: dict[str, Any]) -> str:
    """Return a stable vulnerability class, preferring an explicit scanner classification."""
    explicit = _first_text(
        record,
        ("class", "vulnerability_class", "vulnerability-class", "weakness", "category"),
    )
    if explicit:
        return _slug(explicit)
    candidates = (
        _first_text(
            record,
            ("type", "template-id", "template_id", "rule_id", "RuleID", "cve", "cve_id"),
        ),
        _first_text(record, ("title", "name")),
    )
    for candidate in candidates:
        if not candidate:
            continue
        for pattern, class_name in _CLASS_PATTERNS:
            if pattern.search(candidate):
                return class_name
    raw_type = _slug(str(record.get("type") or ""))
    if raw_type and raw_type not in _GENERIC_TYPES and raw_type != "unknown":
        return raw_type
    return _slug(category)


def normalize_confidence(category: str, record: dict[str, Any]) -> Confidence:
    """Conservatively map heterogeneous scanner confidence to the evidence contract."""
    explicit = _first_text(record, ("confidence", "status", "verification_status"))
    normalized = _slug(explicit) if explicit else ""
    if normalized in CONFIDENCE_ORDER:
        return cast("Confidence", normalized)
    record_type = _slug(str(record.get("type") or ""))
    if (
        record.get("verified") is True
        or "verified" in _slug(category).split("-")
        or "verified" in record_type.split("-")
        or (
            record.get("verification")
            and _slug(str(record.get("verification_confidence") or "")) == "high"
        )
    ):
        return "verified"
    raw_score = record.get("confidence_score")
    try:
        score = float(raw_score) if raw_score is not None else 0.0
    except (TypeError, ValueError):
        score = 0.0
    if normalized in {"high", "certain", "likely"} or score >= _PROBABLE_SCORE:
        return "probable"
    return "lead"


def strongest_confidence(left: Confidence, right: Confidence) -> Confidence:
    return left if CONFIDENCE_ORDER[left] >= CONFIDENCE_ORDER[right] else right


def confidence_rank(value: str) -> int:
    """Return the stable evidence rank, or ``-1`` for an unknown label."""
    return CONFIDENCE_ORDER.get(cast("Confidence", value), -1)


def normalize_finding(  # noqa: PLR0913
    *,
    finding_id: str,
    category: str,
    record: dict[str, Any],
    target: str | None,
    source_refs: tuple[str, ...] = (),
    poc_refs: tuple[str, ...] = (),
) -> FindingEvidence:
    """Normalize one raw scanner record without discarding its native ``details`` payload."""
    category_slug = _slug(category)
    detector = (
        _first_text(record, ("detector", "scanner", "tool"))
        or _DETECTOR_BY_CATEGORY.get(category_slug)
        or category
    )
    request_ref = _first_text(
        record,
        ("request_ref", "request-reference", "request_file", "request-file", "raw_request"),
    )
    verification = _first_text(
        record,
        ("verification_method", "verification-method", "verification", "validation_method"),
    )
    evidence_refs = tuple(dict.fromkeys(
        (*source_refs, *poc_refs, *_refs(record.get("evidence_refs")))
    ))
    control_refs = _refs(
        record.get("control_evidence_refs")
        or record.get("control-evidence-refs")
        or record.get("negative_control_refs")
    )
    return FindingEvidence(
        finding_id=finding_id,
        class_name=normalize_class(category, record),
        target=target,
        request_ref=request_ref,
        confidence=normalize_confidence(category, record),
        detector=_slug(detector),
        verification_method=verification,
        evidence_refs=evidence_refs,
        control_evidence_refs=control_refs,
    )
