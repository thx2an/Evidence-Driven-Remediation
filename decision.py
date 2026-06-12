"""Layer 3 — Cost-aware action selection with blast-radius gating."""

from __future__ import annotations


# ── Catalog lookup ──────────────────────────────────────────────────

def get_action_meta(action_name: str, catalog: list[dict]) -> dict:
    """Look up action metadata from the catalog; returns safe defaults."""
    for a in catalog:
        if a["name"] == action_name:
            return a
    return {
        "name": action_name,
        "cost_min": 10, "downtime_min": 5,
        "blast_radius_services": 3, "rollback_window_sec": 120,
    }


# ── Expected utility ───────────────────────────────────────────────

def compute_expected_utility(
    action_name: str,
    confidence: float,
    catalog: list[dict],
) -> dict:
    """EU = confidence × (1 − cost_penalty / 3)

    Confidence is the dominant signal; cost acts as a moderate
    tie-breaker between actions at similar confidence levels.

    Special handling for ``page_oncall``:  it has zero infrastructure
    cost in the catalog, which would make naïve EV math always prefer
    it.  We inject an *opportunity cost* to represent the human-time
    delay (~30 min average MTTR when paging vs ~12 min when auto-acting).
    """
    meta = get_action_meta(action_name, catalog)
    cost = meta.get("cost_min", 0)
    downtime = meta.get("downtime_min", 0)
    blast = meta.get("blast_radius_services", 0)

    # Normalise cost components to [0, 1]
    cost_norm = min(cost / 20.0, 1.0)
    down_norm = min(downtime / 10.0, 1.0)
    blast_norm = min(blast / 5.0, 1.0)
    cost_penalty = 0.30 * cost_norm + 0.30 * down_norm + 0.40 * blast_norm

    if action_name == "page_oncall":
        # Opportunity cost: humans are slow, paging delays resolution
        cost_penalty = 0.35

    # EU: confidence is dominant, cost is a moderate penalty
    eu = confidence * (1.0 - cost_penalty / 3.0)

    return {
        "action": action_name,
        "confidence": confidence,
        "cost_penalty": round(cost_penalty, 4),
        "expected_utility": round(eu, 4),
        "meta": {
            "cost_min": cost,
            "downtime_min": downtime,
            "blast_radius_services": blast,
            "rollback_window_sec": meta.get("rollback_window_sec", 0),
        },
    }


# ── Blast-radius gate ──────────────────────────────────────────────

def blast_radius_check(
    action_name: str,
    confidence: float,
    catalog: list[dict],
) -> dict:
    """Safety gate: reject actions whose blast radius is too large
    relative to the engine's confidence.

    Rules
    -----
    • ``page_oncall`` always passes (zero blast).
    • confidence < 0.25  ⇒ reject everything with blast > 0.
    • confidence < 0.45  ⇒ reject blast ≥ 3.
    • confidence < 0.55  ⇒ reject blast ≥ 4.
    """
    meta = get_action_meta(action_name, catalog)
    blast = meta.get("blast_radius_services", 0)

    if action_name == "page_oncall":
        return {"passed": True, "reason": "page_oncall: zero blast",
                "blast_radius_services": 0, "confidence": confidence}

    passed, reason = True, "ok"
    if confidence < 0.25 and blast > 0:
        passed, reason = False, (
            f"confidence {confidence:.2f} < 0.25 with blast={blast}")
    elif confidence < 0.45 and blast >= 3:
        passed, reason = False, (
            f"confidence {confidence:.2f} < 0.45 with blast={blast}≥3")
    elif confidence < 0.55 and blast >= 4:
        passed, reason = False, (
            f"confidence {confidence:.2f} < 0.55 with blast={blast}≥4")

    return {
        "passed": passed, "reason": reason,
        "blast_radius_services": blast, "confidence": confidence,
    }


# ── Main action selection ──────────────────────────────────────────

def select_action(
    candidates: dict[str, dict],
    catalog: list[dict],
    max_similarity: float,
    is_ood: bool,
    has_conflict: bool = False,
) -> dict:
    """Pick the single best action (or escalate) from Layer-2 candidates.

    Paths
    -----
    1. **OOD** – force ``page_oncall`` immediately.
    1b. **Conflicting evidence** – dampen confidence (neighbors disagree
        on root cause), making escalation more likely.
    2. **Normal** – compute EU for each candidate, apply blast-radius
       gate, pick highest EU that passes.
    3. **No viable candidate** – escalate to ``page_oncall``.
    """
    # ── Path 1: OOD escalation ──────────────────────────────────
    if is_ood:
        return _build_decision(
            action="page_oncall",
            params={"team": "platform-team"},
            confidence=round(max_similarity, 4),
            reason="OOD: no historical incident closely matches "
                   f"(max_similarity={max_similarity:.3f} < {OOD_THRESHOLD})",
            candidates=candidates, catalog=catalog,
            max_similarity=max_similarity, is_ood=True,
        )

    # ── Path 1b: Conflicting evidence — dampen confidence ───────
    if has_conflict:
        for cdata in candidates.values():
            cdata["confidence"] = round(cdata["confidence"] * 0.55, 4)

    # ── Path 2: EU ranking + blast-radius gate ──────────────────
    ranked, rejected = [], []

    for aname, cdata in candidates.items():
        conf = cdata["confidence"]
        eu_info = compute_expected_utility(aname, conf, catalog)
        br_info = blast_radius_check(aname, conf, catalog)

        entry = {
            "action": aname,
            "confidence": conf,
            "params": cdata["params"],
            "expected_utility": eu_info["expected_utility"],
            "cost_penalty": eu_info["cost_penalty"],
            "blast_check": br_info,
            "voters": cdata.get("voters", []),
            "meta": eu_info["meta"],
        }
        if br_info["passed"]:
            ranked.append(entry)
        else:
            entry["rejected_reason"] = br_info["reason"]
            rejected.append(entry)

    ranked.sort(key=lambda x: x["expected_utility"], reverse=True)

    # ── Path 3: no viable candidate ─────────────────────────────
    if not ranked:
        return _build_decision(
            action="page_oncall",
            params={"team": "platform-team"},
            confidence=round(max(max_similarity * 0.4, 0.05), 4),
            reason="All candidates rejected by blast-radius gate",
            candidates=candidates, catalog=catalog,
            max_similarity=max_similarity, is_ood=False,
            rejected=rejected,
        )

    best = ranked[0]

    # Sanity: if best EU is clearly negative, consider escalation
    if best["expected_utility"] < -0.05 and best["action"] != "page_oncall":
        page_eu = compute_expected_utility(
            "page_oncall", best["confidence"], catalog,
        )
        if page_eu["expected_utility"] > best["expected_utility"]:
            return _build_decision(
                action="page_oncall",
                params={"team": "platform-team"},
                confidence=best["confidence"],
                reason=(f"Best candidate '{best['action']}' has negative EU "
                        f"({best['expected_utility']:.3f}); escalating"),
                candidates=candidates, catalog=catalog,
                max_similarity=max_similarity, is_ood=False,
                rejected=rejected + [best],
            )

    return _build_decision(
        action=best["action"],
        params=best["params"],
        confidence=best["confidence"],
        reason=(f"Highest EU ({best['expected_utility']:.3f}) among "
                f"{len(ranked)} viable candidates"),
        candidates=candidates, catalog=catalog,
        max_similarity=max_similarity, is_ood=False,
        rejected=rejected, ranked=ranked,
    )


# Keep module-level for import in the OOD branch:
from retrieval import OOD_THRESHOLD  # noqa: E402


# ── Decision builder ────────────────────────────────────────────────

def _build_decision(
    *,
    action: str, params: dict, confidence: float, reason: str,
    candidates: dict, catalog: list[dict],
    max_similarity: float, is_ood: bool,
    rejected: list[dict] | None = None,
    ranked: list[dict] | None = None,
) -> dict:
    """Assemble the final decision dict (matches audit.jsonl contract)."""
    meta = get_action_meta(action, catalog)
    br = blast_radius_check(action, confidence, catalog)

    return {
        "selected_action": action,
        "params": params,
        "confidence": round(confidence, 4),
        "consensus_score": round(confidence, 4),
        "reason": reason,
        "is_ood": is_ood,
        "max_similarity": max_similarity,
        "selected_action_meta": {
            "cost_min": meta.get("cost_min", 0),
            "downtime_min": meta.get("downtime_min", 0),
            "blast_radius_services": meta.get("blast_radius_services", 0),
            "blast_radius_check": "passed" if br["passed"] else "failed",
        },
        "all_candidates": {
            aname: {
                "confidence": cd["confidence"],
                "raw_score": cd.get("raw_score", 0),
            }
            for aname, cd in candidates.items()
        },
        "rejected_actions": [
            {"action": r["action"], "reason": r.get("rejected_reason", "")}
            for r in (rejected or [])
        ],
        "ranked_actions": [
            {"action": r["action"], "eu": r["expected_utility"],
             "confidence": r["confidence"]}
            for r in (ranked or [])
        ],
    }
