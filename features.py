"""Layer 1 — Feature extraction from raw incident evidence."""

from __future__ import annotations

import re
from collections import Counter, defaultdict


# ── Log template extraction ──────────────────────────────────────────

_STRIP_PATTERNS = [
    # ISO timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\dZ]*"), "<TS>"),
    # UUIDs
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
    # IP addresses (with optional port)
    (re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?"), "<IP>"),
    # Hex literals (0x...)
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    # Long hex strings (≥8 chars)
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<HEX>"),
    # Standalone numbers
    (re.compile(r"\b\d+(\.\d+)?(%|ms|s|m|MB|GB|KB)?\b"), "<NUM>"),
]


def normalize_log_message(msg: str) -> str:
    """Strip variable parts from a raw log line to produce a template."""
    for pattern, repl in _STRIP_PATTERNS:
        msg = pattern.sub(repl, msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg


def extract_log_features(logs: list[dict]) -> dict:
    """Aggregate raw log entries into templates + service-level stats.

    Returns
    -------
    dict with keys:
        templates        – top-30 normalised templates (list[str])
        raw_messages     – lowercased raw messages (for substring matching)
        error_services   – services that emitted ERROR/FATAL/CRITICAL logs
        service_error_ct – {service: error_count}
    """
    templates: Counter = Counter()
    error_services: set[str] = set()
    svc_error_ct: Counter = Counter()
    raw_messages: list[str] = []

    for entry in logs:
        svc = entry.get("svc", "")
        level = entry.get("level", "INFO").upper()
        msg = entry.get("msg", "")

        raw_messages.append(msg.lower())
        templates[normalize_log_message(msg)] += 1

        if level in ("ERROR", "FATAL", "CRITICAL"):
            error_services.add(svc)
            svc_error_ct[svc] += 1

    return {
        "templates": [t for t, _ in templates.most_common(30)],
        "raw_messages": raw_messages,
        "error_services": error_services,
        "service_error_ct": dict(svc_error_ct),
    }


# ── Trace feature extraction ────────────────────────────────────────

def extract_trace_features(traces: list[dict]) -> dict:
    """Aggregate raw trace records per edge, flag anomalous edges.

    An edge is anomalous when:
      • error_rate > 0.10, **or**
      • p99 / p50 ratio > 2.0  (latency tail blow-up)

    Returns
    -------
    dict with keys:
        anomalous_edges   – list[dict] sorted by severity (descending)
        anomalous_services – set of services on anomalous edges
        edge_features      – dict mapping "from->to" to feature dict
    """
    agg: dict[tuple, dict] = defaultdict(lambda: {
        "count": 0, "error_count": 0,
        "p50_vals": [], "p99_vals": [], "n": 0,
    })

    for t in traces:
        key = (t["from"], t["to"])
        a = agg[key]
        a["count"] += t.get("count", 1)
        a["error_count"] += t.get("error_count", 0)
        a["p50_vals"].append(t.get("p50_ms", 0))
        a["p99_vals"].append(t.get("p99_ms", 0))
        a["n"] += 1

    anomalous: list[dict] = []
    edge_features: dict[str, dict] = {}

    for (frm, to), a in agg.items():
        n = max(a["n"], 1)
        error_rate = a["error_count"] / max(a["count"], 1)
        avg_p50 = sum(a["p50_vals"]) / n
        avg_p99 = sum(a["p99_vals"]) / n
        p99_dev = avg_p99 / max(avg_p50, 1.0)

        feat = {
            "from": frm, "to": to,
            "error_rate": round(error_rate, 4),
            "p99_deviation_ratio": round(p99_dev, 2),
            "avg_p99_ms": round(avg_p99, 1),
            "total_count": a["count"],
            "total_errors": a["error_count"],
        }
        edge_features[f"{frm}->{to}"] = feat

        if error_rate > 0.10 or p99_dev > 2.0:
            anomalous.append(feat)

    anomalous.sort(
        key=lambda e: e["error_rate"] * max(e["p99_deviation_ratio"], 1),
        reverse=True,
    )
    anom_svcs: set[str] = set()
    for e in anomalous:
        anom_svcs.add(e["from"])
        anom_svcs.add(e["to"])

    return {
        "anomalous_edges": anomalous,
        "anomalous_services": anom_svcs,
        "edge_features": edge_features,
    }


# ── Affected service derivation ─────────────────────────────────────

def derive_affected_services(
    incident: dict,
    log_feats: dict,
    trace_feats: dict,
) -> list[str]:
    """Union of trigger service + error-log services + anomalous-trace services."""
    svcs: set[str] = set()

    trigger = incident.get("trigger_alert", {}).get("service")
    if trigger:
        svcs.add(trigger)

    svcs.update(log_feats.get("error_services", set()))
    svcs.update(trace_feats.get("anomalous_services", set()))

    return sorted(svcs)


# ── Root-cause heuristic ────────────────────────────────────────────

def find_root_cause_service(features: dict) -> str:
    """Identify the most likely root-cause service from live evidence.

    Heuristic: score each service by how often it appears as the *callee*
    on anomalous trace edges (weighted by severity). Prefer non-trigger
    services (the trigger usually shows the *symptom*, not the cause).
    For cascades, trace upstream to the deepest anomalous callee.
    """
    anomalies = features.get("trace_anomalies", [])
    trigger = features.get("trigger_service", "")

    if not anomalies:
        # No trace signal — fall back to the service with most error logs
        err_ct = features.get("service_error_ct", {})
        if err_ct:
            return max(err_ct, key=err_ct.get)
        return trigger

    # Score services: `to` side of anomalous edges gets full severity,
    # `from` side gets partial (it's affected but probably not the root).
    svc_score: dict[str, float] = defaultdict(float)
    for a in anomalies:
        severity = a["error_rate"] * max(a["p99_deviation_ratio"], 1.0)
        svc_score[a["to"]] += severity
        svc_score[a["from"]] += severity * 0.25

    # Prefer non-trigger only when it clearly outscores the trigger
    # (the trigger IS the root cause in some incidents, e.g. memory leaks)
    ranked = sorted(svc_score.items(), key=lambda x: x[1], reverse=True)
    non_trigger = [(s, sc) for s, sc in ranked if s != trigger]

    if non_trigger and non_trigger[0][1] >= ranked[0][1] * 0.8:
        return non_trigger[0][0]
    return ranked[0][0] if ranked else trigger


# ── Main entry point ────────────────────────────────────────────────

def extract_features(incident: dict) -> dict:
    """Extract a comparable feature dict from a raw incident JSON."""
    log_feats = extract_log_features(incident.get("logs", []))
    trace_feats = extract_trace_features(incident.get("traces", []))
    affected = derive_affected_services(incident, log_feats, trace_feats)

    return {
        # Identity
        "incident_id": incident.get("incident_id", ""),
        "trigger_service": incident.get("trigger_alert", {}).get("service", ""),
        "trigger_rule": incident.get("trigger_alert", {}).get("rule_id", ""),
        "trigger_severity": incident.get("trigger_alert", {}).get("severity", ""),
        # Services
        "affected_services": affected,
        "error_services": sorted(log_feats["error_services"]),
        "service_error_ct": log_feats["service_error_ct"],
        # Logs
        "log_templates": log_feats["templates"],
        "raw_messages": log_feats["raw_messages"],
        # Traces
        "trace_anomalies": trace_feats["anomalous_edges"],
        "anomalous_services": sorted(trace_feats["anomalous_services"]),
        "edge_features": trace_feats["edge_features"],
        # Root cause
        "root_cause_service": find_root_cause_service({
            **log_feats,
            "trace_anomalies": trace_feats["anomalous_edges"],
            "trigger_service": incident.get("trigger_alert", {}).get("service", ""),
        }),
        # Topology (for downstream analysis)
        "topology": incident.get("topology", {}),
    }
