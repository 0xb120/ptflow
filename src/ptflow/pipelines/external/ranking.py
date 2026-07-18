"""Deterministic risk ranking and stratified request-budget allocation."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

Purpose = Literal["artifact", "dast", "param", "recrawl", "sqli", "xss"]

_STATE_CHANGING = frozenset({"DELETE", "PATCH", "POST", "PUT"})
_AUTH_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization", "x-api-key"})
_HIGH_PATH = frozenset({
    "account", "admin", "api", "callback", "console", "debug", "download", "export", "graphql",
    "import", "internal", "login", "manage", "management", "oauth", "profile", "reset", "settings", "upload",
    "webhook",
})
_URL_PARAMS = frozenset({
    "callback", "continue", "dest", "destination", "domain", "endpoint", "feed", "host", "image",
    "link", "next", "path", "redirect", "return", "returnto", "target", "uri", "url", "webhook",
})
_FILE_PARAMS = frozenset({
    "document", "download", "file", "filename", "folder", "include", "page", "path", "template",
})
_PRIVILEGE_PARAMS = frozenset({
    "admin", "isadmin", "owner", "permission", "permissions", "price", "privilege", "role", "status",
})
_SQLI_PARAMS = frozenset({
    "category", "filter", "id", "item", "order", "product", "query", "search", "sort", "user",
})
_XSS_PARAMS = frozenset({
    "callback", "comment", "description", "html", "keyword", "message", "name", "query", "redirect",
    "return", "search", "text", "title", "url",
})
_STATIC_EXTENSIONS = frozenset({
    "avi", "bmp", "eot", "gif", "ico", "jpeg", "jpg", "mov", "mp3", "mp4", "otf", "pdf", "png",
    "svg", "ttf", "webm", "webp", "woff", "woff2",
})
_GENERIC_SOURCES = frozenset({"", "unknown", "url"})
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8,})$", re.IGNORECASE)
_OPAQUE_SEGMENT = re.compile(r"^[a-z0-9._~%+=-]{16,}$", re.IGNORECASE)
_SECRET_PATH_PARENTS = frozenset({
    "activate", "confirm", "invite", "password", "recover", "reset", "token", "verify",
})
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

_QUOTA_WEIGHT = {
    "authority": 1_000_000,
    "method_class": 100_000,
    "location": 50_000,
    "content_type": 20_000,
    "source": 5_000,
}


@dataclass(frozen=True)
class RankedRequest:
    """One request plus its stable, non-secret score metadata."""

    record: dict[str, Any]
    request_id: str
    shape: str
    score: int
    score_reasons: tuple[str, ...]
    dimensions: dict[str, tuple[str, ...]]
    tie_key: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    """Selection audit record; deliberately excludes bodies, header values, and query values."""

    request_id: str
    shape: str
    score: int
    score_reasons: tuple[str, ...]
    dimensions: dict[str, tuple[str, ...]]
    selected: bool
    selection_rank: int | None
    selection_reason: str | None
    quota_reasons: tuple[str, ...]
    exclusion_reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "shape": self.shape,
            "score": self.score,
            "score_reasons": list(self.score_reasons),
            "dimensions": {key: list(values) for key, values in self.dimensions.items()},
            "selected": self.selected,
            "selection_rank": self.selection_rank,
            "selection_reason": self.selection_reason,
            "quota_reasons": list(self.quota_reasons),
            "exclusion_reason": self.exclusion_reason,
        }


@dataclass(frozen=True)
class Selection:
    """Selected requests, full audit decisions, and aggregate coverage telemetry."""

    records: tuple[dict[str, Any], ...]
    decisions: tuple[Decision, ...]
    limit: int

    def summary(self) -> dict[str, Any]:
        observed = list(self.decisions)
        selected = [decision for decision in observed if decision.selected]
        return {
            "limit": self.limit,
            "observed": len(observed),
            "selected": len(selected),
            "applied": len(observed) > len(selected),
            "distributions": {
                dimension: {
                    "observed": _dimension_counts(observed, dimension),
                    "selected": _dimension_counts(selected, dimension),
                }
                for dimension in (
                    "authority", "method", "method_class", "content_type", "location", "source"
                )
            },
            "scores": {
                "observed": _score_summary(observed),
                "selected": _score_summary(selected),
            },
            "selection_reasons": dict(sorted(Counter(
                decision.selection_reason for decision in selected if decision.selection_reason
            ).items())),
            "exclusion_reasons": dict(sorted(Counter(
                decision.exclusion_reason for decision in observed if decision.exclusion_reason
            ).items())),
        }


def _slug(value: str) -> str:
    return "-".join(token for token in _TOKEN_SPLIT.split(value.casefold()) if token) or "unknown"


def _headers(record: dict[str, Any]) -> dict[str, str]:
    raw = record.get("headers")
    if not isinstance(raw, dict):
        return {}
    return {str(key).casefold(): str(value) for key, value in raw.items()}


def _content_type(record: dict[str, Any]) -> str:
    content_type = _headers(record).get("content-type", "").split(";", 1)[0].strip().casefold()
    body = str(record.get("body") or "").lstrip()
    if not content_type and body:
        content_type = "application/json" if body[:1] in "[{" else "application/x-www-form-urlencoded"
    if "json" in content_type:
        return "json"
    if "multipart" in content_type:
        return "multipart"
    if "x-www-form-urlencoded" in content_type:
        return "form"
    if "xml" in content_type:
        return "xml"
    return _slug(content_type) if content_type else "none"


def _source_family(source: str) -> str:
    value = source.casefold()
    if value.startswith("xref:"):
        family = "xref"
    elif "headless" in value or value in {"browser", "playwright"}:
        family = "browser"
    elif "openapi" in value or "swagger" in value:
        family = "openapi"
    elif "graphql" in value:
        family = "graphql"
    elif "form" in value:
        family = "form"
    elif value in {"jsluice", "xhr"}:
        family = "xhr"
    elif value in {"feroxbuster", "content-discovery", "param_fuzz"}:
        family = "guessed" if value != "param_fuzz" else "param-fuzz"
    else:
        family = _slug(value)
    return family


def _sources(record: dict[str, Any]) -> tuple[str, ...]:
    raw = record.get("sources") or record.get("source") or []
    values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    families = {_source_family(str(value)) for value in values if str(value).strip()}
    return tuple(sorted(family for family in families if family not in _GENERIC_SOURCES))


def _json_names(body: str) -> list[str]:
    if not body.lstrip().startswith("{"):
        return []
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(key) for key in value] if isinstance(value, dict) else []


def _parameter_locations(record: dict[str, Any]) -> dict[str, set[str]]:
    locations: dict[str, set[str]] = {}
    for parameter in record.get("params") or []:
        if not isinstance(parameter, dict) or not parameter.get("name"):
            continue
        location = _slug(str(parameter.get("loc") or "query"))
        locations.setdefault(location, set()).add(str(parameter["name"]).casefold())
    parts = urlsplit(str(record.get("url") or ""))
    query_names = {key.casefold() for key, _ in parse_qsl(parts.query, keep_blank_values=True) if key}
    if query_names:
        locations.setdefault("query", set()).update(query_names)
    body = str(record.get("body") or "")
    content_type = _content_type(record)
    if body and content_type == "json":
        locations.setdefault("json", set()).update(name.casefold() for name in _json_names(body))
    elif body and content_type == "form":
        locations.setdefault("body", set()).update(
            key.casefold() for key, _ in parse_qsl(body, keep_blank_values=True) if key
        )
    return locations


def _authority(record: dict[str, Any]) -> str:
    parts = urlsplit(str(record.get("url") or ""))
    netloc = _safe_netloc(parts)
    return f"{parts.scheme.casefold()}://{netloc}" if netloc else "unknown"


def _safe_netloc(parts: Any) -> str:
    """Authority without URL userinfo, which may contain credentials."""
    host = (parts.hostname or "").casefold()
    if not host:
        return ""
    rendered = f"[{host}]" if ":" in host else host
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{rendered}:{port}" if port is not None else rendered


def _shape_path(url: str) -> str:
    parts = urlsplit(url)
    segments: list[str] = []
    previous = ""
    for segment in parts.path.split("/"):
        redact = (
            previous.casefold() in _SECRET_PATH_PARENTS
            or bool(_ID_SEGMENT.fullmatch(segment))
            or bool(_OPAQUE_SEGMENT.fullmatch(segment))
        )
        segments.append("*" if segment and redact else segment)
        previous = segment
    path = "/".join(segments) or "/"
    query_names = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True) if key})
    suffix = f"?{','.join(query_names)}" if query_names else ""
    return f"{parts.scheme.casefold()}://{_safe_netloc(parts)}{path}{suffix}"


def _request_identity(record: dict[str, Any], dimensions: dict[str, tuple[str, ...]]) -> tuple[str, str]:
    method = str(record.get("method") or "GET").upper()
    shape = f"{method} {_shape_path(str(record.get('url') or ''))}"
    payload = {
        "shape": shape,
        "content_type": dimensions["content_type"],
        "locations": dimensions["location"],
        "parameters": {
            location: sorted(names) for location, names in _parameter_locations(record).items()
        },
        "sources": dimensions["source"],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return digest, shape


def _score_common(  # noqa: C901, PLR0912, PLR0915
    record: dict[str, Any], purpose: Purpose,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"{points:+d}:{reason}")

    method = str(record.get("method") or "GET").upper()
    headers = _headers(record)
    content_type = _content_type(record)
    locations = _parameter_locations(record)
    names = {name for values in locations.values() for name in values}
    path_tokens = {token for token in _TOKEN_SPLIT.split(urlsplit(
        str(record.get("url") or "")
    ).path.casefold()) if token}
    sources = _sources(record)
    auth_context = str(record.get("auth_context") or "").casefold()
    if _AUTH_HEADERS.intersection(headers) or auth_context not in {"", "anonymous", "none"}:
        add(35, "authenticated")
    if method in _STATE_CHANGING:
        add(24, f"state-changing:{method}")
    elif method != "GET":
        add(12, f"non-get:{method}")
    if content_type == "json":
        add(24, "json-body")
    elif content_type == "multipart":
        add(26, "multipart-body")
    elif content_type == "form":
        add(18, "form-body")
    elif content_type == "xml":
        add(22, "xml-body")
    if record.get("body"):
        add(8, "body-bearing")
    if locations:
        add(min(18, 4 + sum(len(values) for values in locations.values()) * 2), "parameters")
    for source in sources:
        source_points = {
            "browser": 24, "form": 22, "graphql": 26, "openapi": 24, "param-fuzz": 28,
            "xhr": 24, "xref": 16,
        }.get(source, 8)
        add(source_points, f"source:{source}")
    valuable_paths = sorted(path_tokens.intersection(_HIGH_PATH))
    if valuable_paths:
        add(min(30, len(valuable_paths) * 10), f"high-value-path:{','.join(valuable_paths)}")
    if names.intersection(_URL_PARAMS):
        add(22, "url-like-parameter")
    if names.intersection(_FILE_PARAMS):
        add(18, "file-like-parameter")
    if names.intersection(_PRIVILEGE_PARAMS):
        add(20, "privilege-parameter")
    status = record.get("status")
    if isinstance(status, int) and 200 <= status < 400:  # noqa: PLR2004
        add(12, f"live-status:{status // 100}xx")
    elif status in {401, 403}:
        add(10, f"access-controlled:{status}")
    if purpose == "sqli" and names.intersection(_SQLI_PARAMS):
        add(24, "sqli-relevant-parameter")
    if purpose == "xss" and names.intersection(_XSS_PARAMS):
        add(24, "xss-relevant-parameter")
    if purpose == "param" and valuable_paths:
        add(10, "parameter-discovery-path")
    if purpose == "artifact":
        length = record.get("length")
        if isinstance(length, int) and length > 0:
            add(min(12, max(1, length.bit_length() - 7)), "content-bearing")
    path = urlsplit(str(record.get("url") or "")).path
    extension = path.rsplit(".", 1)[-1].casefold() if "." in path.rsplit("/", 1)[-1] else ""
    if method == "GET" and not locations and extension in _STATIC_EXTENSIONS:
        add(-25, "static-fetch")
    if purpose == "recrawl":
        depth = len([segment for segment in path.split("/") if segment])
        if depth > 1:
            add(-min(12, (depth - 1) * 2), "deep-recrawl-seed")
    return score, reasons


def _dimensions(record: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    method = str(record.get("method") or "GET").upper()
    locations = tuple(sorted(_parameter_locations(record)))
    return {
        "authority": (_authority(record),),
        "method": (method,),
        "method_class": ("GET" if method == "GET" else "NON_GET",),
        "content_type": (_content_type(record),),
        "location": locations,
        "source": _sources(record),
    }


def score_request(record: dict[str, Any], *, purpose: Purpose = "dast") -> RankedRequest:
    """Score one request without using discovery order or sensitive values."""
    dimensions = _dimensions(record)
    score, reasons = _score_common(record, purpose)
    request_id, shape = _request_identity(record, dimensions)
    return RankedRequest(
        record=record,
        request_id=request_id,
        shape=shape,
        score=score,
        score_reasons=tuple(reasons),
        dimensions=dimensions,
        tie_key=(shape, request_id),
    )


def _with_novelty(items: list[RankedRequest]) -> list[RankedRequest]:
    counts = Counter(
        (dimension, value)
        for item in items
        for dimension in ("method", "content_type", "location", "source")
        for value in item.dimensions[dimension]
    )
    threshold = max(1, len(items) // 10)
    out: list[RankedRequest] = []
    for item in items:
        rare = sorted(
            f"{dimension}:{value}"
            for dimension in ("method", "content_type", "location", "source")
            for value in item.dimensions[dimension]
            if counts[dimension, value] <= threshold
        )
        bonus = min(12, len(rare) * 3)
        out.append(replace(
            item,
            score=item.score + bonus,
            score_reasons=(*item.score_reasons, *((f"+{bonus}:novel:{','.join(rare)}",) if bonus else ())),
        ))
    return out


def _strata(item: RankedRequest) -> set[str]:
    return {
        f"{dimension}:{value}"
        for dimension in _QUOTA_WEIGHT
        for value in item.dimensions[dimension]
        if value not in {"none", "unknown"}
    }


def _quota_gain(strata: set[str]) -> int:
    return sum(_QUOTA_WEIGHT[item.split(":", 1)[0]] for item in strata)


def allocate(
    records: list[dict[str, Any]], *, cap: int, purpose: Purpose = "dast",
) -> Selection:
    """Select a stable risk-ranked set with coverage quotas before score-only fill."""
    ranked = sorted(
        _with_novelty([score_request(record, purpose=purpose) for record in records]),
        key=lambda item: (-item.score, item.tie_key),
    )
    limit = max(0, cap)
    uncovered = set().union(*(_strata(item) for item in ranked)) if ranked else set()
    chosen: set[int] = set()
    quota_reasons: dict[int, tuple[str, ...]] = {}
    while uncovered and len(chosen) < limit:
        candidates = []
        for index, item in enumerate(ranked):
            if index in chosen:
                continue
            newly_covered = _strata(item).intersection(uncovered)
            if newly_covered:
                candidates.append((index, newly_covered, _quota_gain(newly_covered)))
        if not candidates:
            break
        index, covered, _ = min(
            candidates,
            key=lambda candidate: (
                -candidate[2], -ranked[candidate[0]].score, ranked[candidate[0]].tie_key,
            ),
        )
        chosen.add(index)
        quota_reasons[index] = tuple(sorted(covered))
        uncovered.difference_update(covered)
    for index in range(len(ranked)):
        if len(chosen) >= limit:
            break
        chosen.add(index)

    selected_indexes = [index for index in range(len(ranked)) if index in chosen]
    selection_rank = {index: rank for rank, index in enumerate(selected_indexes, start=1)}
    decisions = tuple(
        Decision(
            request_id=item.request_id,
            shape=item.shape,
            score=item.score,
            score_reasons=item.score_reasons,
            dimensions=item.dimensions,
            selected=index in chosen,
            selection_rank=selection_rank.get(index),
            selection_reason=("quota" if index in quota_reasons else "score")
            if index in chosen else None,
            quota_reasons=quota_reasons.get(index, ()),
            exclusion_reason=None if index in chosen else "budget-exhausted",
        )
        for index, item in enumerate(ranked)
    )
    return Selection(
        records=tuple(ranked[index].record for index in selected_indexes),
        decisions=decisions,
        limit=limit,
    )


def allocate_group_budgets(
    demands: Mapping[str, int], *, per_group_cap: int,
) -> dict[str, int]:
    """Redistribute unused per-group capacity without increasing the engagement budget.

    Every group first receives up to its observed demand. Capacity left by small groups is then
    water-filled across groups whose demand exceeds the original cap. Ties are stable by group id.
    The returned allocations never exceed either demand or ``per_group_cap * len(demands)`` in total.
    """
    cap = max(0, per_group_cap)
    normalized = {group: max(0, int(demand)) for group, demand in sorted(demands.items())}
    allocations = {group: min(demand, cap) for group, demand in normalized.items()}
    remaining = cap * len(normalized) - sum(allocations.values())
    while remaining:
        active = [
            group for group, demand in normalized.items() if allocations[group] < demand
        ]
        if not active:
            break
        share = remaining // len(active)
        if share == 0:
            for group in sorted(
                active, key=lambda item: (-(normalized[item] - allocations[item]), item),
            )[:remaining]:
                allocations[group] += 1
            break
        granted = 0
        for group in active:
            amount = min(share, normalized[group] - allocations[group])
            allocations[group] += amount
            granted += amount
        if granted == 0:
            break
        remaining -= granted
    return allocations


def _dimension_counts(decisions: list[Decision], dimension: str) -> dict[str, int]:
    counts = Counter(
        value for decision in decisions for value in decision.dimensions.get(dimension, ())
    )
    return dict(sorted(counts.items()))


def _score_summary(decisions: list[Decision]) -> dict[str, float | int | None]:
    if not decisions:
        return {"min": None, "max": None, "average": None}
    scores = [decision.score for decision in decisions]
    return {
        "min": min(scores),
        "max": max(scores),
        "average": round(sum(scores) / len(scores), 2),
    }
