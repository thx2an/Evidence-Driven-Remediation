"""Evidence-Driven Remediation Engine — CLI entry point.

Usage
-----
    python engine.py decide --incident eval/E01.json \\
                            --history incidents_history.json \\
                            --actions actions.yaml

Prints the engine's decision as JSON to stdout and appends one line
to ``audit.jsonl``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from features import extract_features, find_root_cause_service
from retrieval import retrieve_and_vote
from decision import select_action


# ── Param adaptation ────────────────────────────────────────────────

def adapt_candidate_params(
    candidates: dict[str, dict],
    features: dict,
    catalog: list[dict],
) -> dict[str, dict]:
    """Ensure action params reference services from the *live* incident.

    Historical voting may return params targeting services from past
    incidents. If those services don't appear in the current incident's
    affected set we replace them with the most likely root-cause service
    derived from live evidence.
    """
    affected = set(features.get("affected_services", []))
    root_cause = features.get("root_cause_service", "")

    for aname, cdata in candidates.items():
        params = dict(cdata.get("params", {}))

        # For service-scoped actions, verify / adapt the service param
        cat_entry = next((a for a in catalog if a["name"] == aname), None)
        if cat_entry and "service" in cat_entry.get("params", []):
            hist_svc = params.get("service", "")
            if not hist_svc or hist_svc not in affected:
                params["service"] = root_cause or (
                    features.get("trigger_service", ""))

        # Defaults for optional params
        if aname == "rollback_service":
            params.setdefault("target_version", "previous")
        if aname == "restart_pod":
            params.setdefault("pod_selector", "default")
        if aname == "page_oncall":
            params.setdefault("team", "platform-team")

        cdata["params"] = params

    return candidates


# ── Core pipeline ───────────────────────────────────────────────────

def decide(incident_path: Path, history_path: Path, actions_path: Path) -> dict:
    """Run the full three-layer pipeline and return an audit-ready dict."""
    incident = json.loads(incident_path.read_text())
    history = json.loads(history_path.read_text())
    catalog = yaml.safe_load(actions_path.read_text())

    # Layer 1 — feature extraction
    features = extract_features(incident)

    # Layer 2 — retrieval + outcome-weighted voting
    retrieval = retrieve_and_vote(features, history, catalog)

    # Adapt params to target live-incident services
    adapt_candidate_params(retrieval["candidates"], features, catalog)

    # Layer 3 — cost-aware action selection
    decision = select_action(
        retrieval["candidates"],
        catalog,
        retrieval["max_similarity"],
        retrieval["is_ood"],
        retrieval.get("has_conflict", False),
    )

    # If selected action needs service param, ensure it's set
    if decision["selected_action"] == "page_oncall":
        decision["params"].setdefault("team", "platform-team")
    else:
        cat_entry = next(
            (a for a in catalog if a["name"] == decision["selected_action"]),
            None,
        )
        if cat_entry and "service" in cat_entry.get("params", []):
            if not decision["params"].get("service"):
                decision["params"]["service"] = (
                    features.get("root_cause_service", "")
                    or features.get("trigger_service", "")
                )

    # ── Build audit entry ───────────────────────────────────────
    incident_id = incident_path.stem          # E01, E02, …

    audit_entry = {
        "incident_id": incident_id,
        "selected_action": decision["selected_action"],
        "params": decision["params"],
        "confidence": decision["confidence"],
        "consensus_score": decision["consensus_score"],
        # Required for auto-grader scoring:
        "top_3_neighbors": retrieval["neighbors"][:3],
        "selected_action_meta": decision["selected_action_meta"],
        # Option B — Justification Chain:
        "evidence": {
            "affected_services": features["affected_services"],
            "root_cause_service": features.get("root_cause_service", ""),
            "trigger": {
                "service": features["trigger_service"],
                "rule": features["trigger_rule"],
                "severity": features["trigger_severity"],
            },
            "log_templates_top5": features["log_templates"][:5],
            "trace_anomalies": [
                {
                    "from": a["from"], "to": a["to"],
                    "error_rate": a["error_rate"],
                    "p99_deviation_ratio": a["p99_deviation_ratio"],
                }
                for a in features["trace_anomalies"][:5]
            ],
            "retrieval_summary": {
                "max_similarity": retrieval["max_similarity"],
                "is_ood": retrieval["is_ood"],
                "num_candidates": len(retrieval["candidates"]),
                "top_neighbors": [
                    {
                        "id": n["id"],
                        "similarity": n["similarity"],
                        "outcome": n["outcome"],
                        "root_cause_class": n["root_cause_class"],
                    }
                    for n in retrieval["neighbors"][:5]
                ],
            },
            "decision_rationale": {
                "reason": decision["reason"],
                "is_ood": decision["is_ood"],
                "all_candidates": decision["all_candidates"],
                "rejected_actions": decision["rejected_actions"],
                "ranked_actions": decision["ranked_actions"],
            },
        },
    }

    return audit_entry


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evidence-Driven Remediation Engine",
    )
    sub = parser.add_subparsers(dest="cmd")

    dec = sub.add_parser("decide", help="Analyse an incident and recommend an action")
    dec.add_argument("--incident", required=True, help="Path to incident JSON")
    dec.add_argument("--history", default="incidents_history.json",
                     help="Path to historical incidents JSON")
    dec.add_argument("--actions", default="actions.yaml",
                     help="Path to actions catalog YAML")

    args = parser.parse_args()

    if args.cmd == "decide":
        result = decide(Path(args.incident), Path(args.history), Path(args.actions))
        print(json.dumps(result, indent=2))

        with open("audit.jsonl", "a") as f:
            f.write(json.dumps(result) + "\n")

        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
