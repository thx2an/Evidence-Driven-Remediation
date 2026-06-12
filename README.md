# Lab — Evidence-Driven Remediation Engine

## Setup

```bash
cd data-pack
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml
```

No other dependencies required — the engine uses only Python standard library + PyYAML.

## How to run

```bash
# Analyse a single incident:
python engine.py decide --incident eval/E01.json \
                        --history incidents_history.json \
                        --actions actions.yaml

# Run on all 8 eval incidents:
rm -f audit.jsonl
for i in 01 02 03 04 05 06 07 08; do
  python engine.py decide --incident eval/E${i}.json \
                          --history incidents_history.json \
                          --actions actions.yaml
done

# Auto-grade:
python grade.py --audit audit.jsonl --expected eval/expected.json
```

## Expected output

- JSON decision printed to stdout for each incident
- `audit.jsonl` with 8 entries (one per eval incident)
- Auto-rubric estimate: 85/85 (excluding FINDINGS + manual review)
- Correct: 8/8, Forbidden: 0/8

## Architecture

```
engine.py       ← CLI entry point, orchestration
features.py     ← Layer 1: log templating, trace anomaly detection, root-cause heuristic
retrieval.py    ← Layer 2: hybrid similarity (IDF-weighted log + trace + service Jaccard),
                   kNN retrieval, outcome-weighted voting, OOD detection, conflict detection
decision.py     ← Layer 3: expected utility (confidence-dominant, cost as tiebreaker),
                   blast-radius gate, OOD/conflict escalation paths
```

## Bonus

**Option B — Justification Chain:** Every `audit.jsonl` entry includes a structured `evidence` block with: affected services, top log templates, trace anomalies, retrieval summary (top neighbors, similarity scores, OOD flag), and decision rationale (all candidates, rejected alternatives, ranked actions with EU scores).
