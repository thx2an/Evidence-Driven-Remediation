"""Layer 2 — Similarity-based retrieval and outcome-weighted action voting."""

from __future__ import annotations

import math
from collections import Counter, defaultdict


# ── Outcome weights (how much we trust each historical outcome) ─────

OUTCOME_WEIGHT: dict[str, float] = {
    "success": 1.0,
    "partial": 0.40,
    "failed":  0.05,
}

# ── OOD threshold ───────────────────────────────────────────────────
OOD_THRESHOLD = 0.25   # below this → incident is out-of-distribution


# ── IDF for log signatures ──────────────────────────────────────────

def compute_log_idf(history: list[dict]) -> dict[str, float]:
    """Inverse-document-frequency weights for each log signature.

    Specific signatures (e.g. "ConnectionPool: timeout acquiring connection")
    appear in few entries → high weight.  Generic ones ("degraded behavior
    detected") appear in many → low weight.
    """
    n = len(history)
    doc_freq: Counter = Counter()
    for entry in history:
        for sig in set(entry.get("log_signatures", [])):
            doc_freq[sig] += 1
    return {sig: math.log(n / count) + 1.0 for sig, count in doc_freq.items()}


# ── Similarity components ───────────────────────────────────────────

def log_similarity(
    raw_messages: list[str],
    hist_signatures: list[str],
    idf: dict[str, float] | None = None,
) -> float:
    """IDF-weighted coverage: fraction of historical signatures found in
    the live log messages (weighted by informativeness).
    """
    if not hist_signatures:
        return 0.0

    total_w = 0.0
    matched_w = 0.0
    for sig in hist_signatures:
        w = idf.get(sig, 1.0) if idf else 1.0
        total_w += w
        sig_low = sig.lower()
        for raw in raw_messages:
            if sig_low in raw:
                matched_w += w
                break

    return matched_w / max(total_w, 1e-6)


def trace_similarity(
    live_anomalies: list[dict],
    hist_trace_sigs: list[dict],
) -> float:
    """Edge-match score between live trace anomalies and historical sigs."""
    if not hist_trace_sigs and not live_anomalies:
        return 0.50          # both empty → neutral
    if not hist_trace_sigs:
        return 0.15          # history has no traces, live does → weak mismatch
    if not live_anomalies:
        return 0.10          # history expects traces, live has none → mismatch

    total = 0.0
    for hsig in hist_trace_sigs:
        h_from, h_to = hsig["from"], hsig["to"]
        h_err = hsig.get("error_rate", 0.0)
        best = 0.0
        for la in live_anomalies:
            l_from, l_to = la["from"], la["to"]
            if (h_from == l_from and h_to == l_to) or \
               (h_from == l_to and h_to == l_from):
                # Edge matches — score by error-rate closeness
                if h_err > 0 and la["error_rate"] > 0:
                    ratio = min(la["error_rate"], h_err) / max(la["error_rate"], h_err)
                    best = max(best, 0.5 + 0.5 * ratio)
                else:
                    best = max(best, 0.50)
        total += best

    return total / len(hist_trace_sigs)


def service_similarity(
    live_services: list[str],
    hist_services: list[str],
) -> float:
    """Jaccard index on affected-service sets."""
    s_live = set(live_services)
    s_hist = set(hist_services)
    if not s_live and not s_hist:
        return 0.50
    if not s_live or not s_hist:
        return 0.0
    return len(s_live & s_hist) / len(s_live | s_hist)


def compute_similarity(
    features: dict,
    hist_entry: dict,
    idf: dict[str, float] | None = None,
) -> tuple[float, dict]:
    """Weighted hybrid similarity between a live feature-set and a
    historical corpus entry.

    Base weights: log 0.40 · trace 0.35 · service 0.25

    Coherence check: when the live incident has a *strong* dominant
    trace anomaly (error_rate > 0.15) but a historical entry's trace
    signatures do NOT match that dominant edge, we apply a penalty.
    This handles conflicting-evidence cases where logs mislead.
    """
    log_sim = log_similarity(
        features.get("raw_messages", []),
        hist_entry.get("log_signatures", []),
        idf,
    )
    trace_sim = trace_similarity(
        features.get("trace_anomalies", []),
        hist_entry.get("trace_signatures", []),
    )
    svc_sim = service_similarity(
        features.get("affected_services", []),
        hist_entry.get("affected_services", []),
    )

    score = 0.40 * log_sim + 0.35 * trace_sim + 0.25 * svc_sim

    # ── Coherence penalty ────────────────────────────────────────
    # If the live incident has a dominant trace anomaly, check whether
    # this historical entry's trace signatures are coherent with it.
    live_anomalies = features.get("trace_anomalies", [])
    hist_trace_sigs = hist_entry.get("trace_signatures", [])
    if live_anomalies and hist_trace_sigs:
        dominant = live_anomalies[0]  # sorted by severity
        if dominant["error_rate"] > 0.15:
            dom_edge = (dominant["from"], dominant["to"])
            # Does any historical trace sig match the dominant edge?
            matches_dominant = any(
                (hs["from"] == dom_edge[0] and hs["to"] == dom_edge[1]) or
                (hs["from"] == dom_edge[1] and hs["to"] == dom_edge[0])
                for hs in hist_trace_sigs
            )
            if not matches_dominant:
                # Historical entry's traces point elsewhere — penalise
                score *= 0.55

    breakdown = {
        "log_similarity": round(log_sim, 4),
        "trace_similarity": round(trace_sim, 4),
        "service_similarity": round(svc_sim, 4),
    }
    return round(score, 4), breakdown


# ── Action parsing ──────────────────────────────────────────────────

def parse_history_action(action_str: str, catalog: list[dict]) -> dict:
    """Parse "action:param1:param2" → {name, params: {named_key: val}}."""
    parts = action_str.split(":")
    name = parts[0]
    positional = parts[1:]

    cat_entry = next((a for a in catalog if a["name"] == name), None)
    params: dict[str, str] = {}
    if cat_entry:
        for i, pname in enumerate(cat_entry.get("params", [])):
            if i < len(positional):
                params[pname] = positional[i]
    else:
        for i, v in enumerate(positional):
            params[f"param{i}"] = v

    return {"name": name, "params": params}


# ── Main: retrieve + vote ───────────────────────────────────────────

def retrieve_and_vote(
    features: dict,
    history: list[dict],
    catalog: list[dict],
    top_k: int = 5,
) -> dict:
    """k-NN retrieval over the historical corpus with outcome-weighted
    action voting.

    Returns
    -------
    dict with keys:
        neighbors      – top-k neighbours with similarity scores
        candidates     – {action_name: {confidence, params, voters, …}}
        max_similarity – float, highest similarity in the corpus
        is_ood         – bool, True when max_similarity < OOD_THRESHOLD
    """
    idf = compute_log_idf(history)

    # Score every historical entry
    scored: list[tuple[float, dict, dict]] = []
    for entry in history:
        sim, breakdown = compute_similarity(features, entry, idf)
        scored.append((sim, entry, breakdown))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:top_k]

    max_sim = top[0][0] if top else 0.0
    is_ood = max_sim < OOD_THRESHOLD

    # ── Outcome-weighted voting ──────────────────────────────────
    action_votes: dict[str, dict] = defaultdict(lambda: {
        "weighted_score": 0.0,
        "voters": [],
        "params_options": [],
    })

    for sim, entry, breakdown in top:
        if sim < 0.10:
            continue                     # ignore very distant neighbours

        outcome = entry.get("outcome", "failed")
        ow = OUTCOME_WEIGHT.get(outcome, 0.1)
        vote_w = (sim ** 2) * ow          # quadratic: amplifies top matches

        for action_str in entry.get("actions_taken", []):
            parsed = parse_history_action(action_str, catalog)
            aname = parsed["name"]

            bucket = action_votes[aname]
            bucket["weighted_score"] += vote_w
            bucket["voters"].append({
                "id": entry["id"],
                "similarity": sim,
                "outcome": outcome,
                "vote_weight": round(vote_w, 4),
                "sim_breakdown": breakdown,
                "root_cause_class": entry.get("root_cause_class", ""),
            })
            bucket["params_options"].append(parsed["params"])

    # ── Normalise → confidence per action ────────────────────────
    total_w = sum(v["weighted_score"] for v in action_votes.values())
    candidates: dict[str, dict] = {}
    for aname, data in action_votes.items():
        confidence = data["weighted_score"] / max(total_w, 1e-6)
        best_params = _pick_best_params(data["params_options"])

        candidates[aname] = {
            "confidence": round(confidence, 4),
            "raw_score": round(data["weighted_score"], 4),
            "voters": data["voters"],
            "params": best_params,
        }

    # ── Build neighbour list for audit ───────────────────────────
    neighbors = []
    for sim, entry, breakdown in top:
        neighbors.append({
            "id": entry["id"],
            "similarity": round(sim, 4),
            "outcome": entry.get("outcome", ""),
            "root_cause_class": entry.get("root_cause_class", ""),
            "actions_taken": entry.get("actions_taken", []),
            "sim_breakdown": breakdown,
        })

    # ── Conflict detection ────────────────────────────────────────
    # When top neighbors disagree on root_cause_class, evidence is
    # conflicting → decision layer should lower confidence.
    rc_classes = [
        entry.get("root_cause_class", "")
        for sim, entry, _ in top
        if sim > 0.25
    ]
    has_conflict = len(set(rc_classes)) >= 2 and len(rc_classes) >= 3

    return {
        "neighbors": neighbors,
        "candidates": candidates,
        "max_similarity": round(max_sim, 4),
        "is_ood": is_ood,
        "has_conflict": has_conflict,
    }


def _pick_best_params(params_list: list[dict]) -> dict:
    """Pick the most common non-empty param set from voter suggestions."""
    if not params_list:
        return {}
    # Frequency count by stringified params
    counts: Counter = Counter()
    lookup: dict[str, dict] = {}
    for p in params_list:
        key = str(sorted(p.items()))
        counts[key] += 1
        lookup[key] = p
    best_key = counts.most_common(1)[0][0]
    return lookup[best_key]
