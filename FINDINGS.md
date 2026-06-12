# FINDINGS.md — Evidence-Driven Remediation Engine

> All numbers below are taken directly from the committed `audit.jsonl`
> (run with `python engine.py decide ...` on E01–E08). They are
> reproducible from the evidence blocks in that file.

## 1. Which similarity function did you choose for Layer 2, and why?

I chose a **weighted hybrid similarity** combining three components, plus a
coherence penalty:

| Component | Weight | Method |
|-----------|--------|--------|
| Log similarity | 0.40 | IDF-weighted coverage of historical log signatures found (as substrings) in the live raw messages |
| Trace similarity | 0.35 | Edge-match score: match historical trace edges to live anomalous edges by `(from,to)` pair, score by error-rate closeness |
| Service overlap | 0.25 | Jaccard index on affected-service sets |

**Key design choice — IDF-weighted log matching.** Generic signatures like
`"degraded behavior detected"` appear in **15/29** historical entries
(IDF = ln(29/15)+1 ≈ **1.66**), while specific ones like
`"ConnectionPool: timeout acquiring connection"` appear in only **3/29**
(IDF ≈ **3.27**). Without IDF weighting, generic signatures would make every
incident look similar to half the corpus. (Both numbers verified against
`incidents_history.json`, n=29.)

**Alternative considered — Cosine similarity on TF-IDF vectors.** I considered
encoding both live and historical incidents as TF-IDF vectors over normalised
log templates and computing cosine distance. I rejected it because:
1. The corpus has only 29 entries — too few to build a meaningful vocabulary;
   a high-dimensional TF-IDF vector would overfit on so few neighbours.
2. Substring containment directly leverages the fact that historical
   `log_signatures` are *cleaned templates* while live logs are *raw messages*.
   Cosine would require converting both to one representation first, adding a
   fragile step.

**Empirical validation.** On **E01** (pool exhaustion) the hybrid similarity
ranks `INC-2025-11-08` (connection_pool_exhaustion, success) at the top with
**sim = 0.641**, well clear of the next neighbours which drop to **0.247**
(`INC-2025-09-05` / `INC-2026-05-10`, same class) and **0.158**
(`INC-2025-07-04`, lock_contention — a *different* class). A pure log-only
similarity would not separate E01 from E06 nearly as cleanly, because E06's
logs *also* contain pool-exhaustion lines.

**Coherence penalty.** When the live incident has a strong dominant trace
anomaly (`error_rate > 0.15`) but a historical entry's trace signatures don't
match that dominant edge, similarity is multiplied by **×0.55**. This is what
handles **E06**: the dominant live anomaly is `cart-svc → cart-redis`
(`error_rate = 0.21`, `p99_deviation_ratio = 5.96`), but the high-log-match
`connection_pool_exhaustion` history entries all describe `checkout → payment`
edges, so they are penalised — their similarity drops to **0.38 / 0.36**
instead of dominating on log match alone.

---

## 2. How does outcome-weighted voting change the candidate ranking versus a pure-similarity ranking?

**Outcome weights:** `success = 1.0`, `partial = 0.40`, `failed = 0.05`.
**Vote weight:** `vote_weight = similarity² × outcome_weight`
(`similarity²` amplifies the top match and suppresses distant neighbours).

**Concrete example — E01, where outcome weighting flips the *shipped* action.**

E01's voting neighbours (sim ≥ 0.10) and the actions each contributes:

| Neighbour | sim | outcome | actions contributed |
|-----------|-----|---------|---------------------|
| INC-2025-11-08 | 0.641 | success | rollback_service, increase_pool_size |
| INC-2025-09-05 | 0.247 | success | rollback_service, increase_pool_size |
| INC-2026-05-10 | 0.247 | **partial** | rollback_service *(only)* |
| INC-2025-07-04 | 0.158 | success | restart_pod |
| INC-2026-02-22 | 0.140 | success | page_oncall |

The only difference between `rollback_service` and `increase_pool_size` is the
**partial-outcome** neighbour `INC-2026-05-10`, which used rollback *alone* and
only partially resolved the incident.

| Action | Pure-similarity raw vote (Σ sim²) | Outcome-weighted raw vote (Σ sim²·w) |
|--------|-----------------------------------|--------------------------------------|
| `rollback_service` | 0.4105 + 0.0611 + 0.0611 = **0.533** | 0.4105 + 0.0611 + (0.0611×0.4) = **0.496** |
| `increase_pool_size` | 0.4105 + 0.0611 = **0.472** | 0.4105 + 0.0611 = **0.472** |

The partial discount shrinks rollback's lead over increase from **0.061**
(pure) to **0.024** (weighted). That compression is decisive once Layer 3
applies cost:

- **Pure-similarity** → confidences `rollback 0.508 / increase 0.450` →
  EU `rollback 0.459` vs `increase 0.435` → **rollback ships**.
- **Outcome-weighted** → confidences `rollback 0.490 / increase 0.466` →
  EU `increase 0.451` vs `rollback 0.443` → **increase_pool_size ships**.

So outcome weighting does more than re-score: by discounting the lone
partial-outcome rollback, it lets the **cheaper** `increase_pool_size`
(cost 1, downtime 0) overtake the costlier `rollback_service` (cost 10,
downtime 2) on expected utility. Both are accepted actions for E01, so the
decision stays correct — but the action the engine actually ships changes.

---

## 3. For one eval incident, explain the EV calculation in full

**E01 — connection pool exhaustion → ships `increase_pool_size`.**

### Candidate set from Layer 2 (outcome-weighted confidence)

| Action | Confidence | Raw score |
|--------|-----------|-----------|
| `rollback_service`   | 0.4901 | 0.496 |
| `increase_pool_size` | 0.4660 | 0.472 |
| `restart_pod`        | 0.0246 | 0.025 |
| `page_oncall`        | 0.0194 | 0.020 |

### EU formula: `EU = confidence × (1 − cost_penalty / 3)`

where `cost_penalty = 0.30·(cost/20) + 0.30·(downtime/10) + 0.40·(blast/5)`,
and `page_oncall` uses a fixed opportunity cost of `0.35`.

| Action | Confidence | cost_penalty | EU | Blast gate |
|--------|-----------|-------------|-----|-----------|
| `increase_pool_size` | 0.466 | 0.095 | 0.466 × (1 − 0.0317) = **0.4512** | PASS (blast=1) |
| `rollback_service`   | 0.490 | 0.290 | 0.490 × (1 − 0.0967) = **0.4427** | PASS (blast=1) |
| `page_oncall`        | 0.019 | 0.350 | 0.019 × (1 − 0.1167) = **0.0171** | PASS (blast=0) |
| `restart_pod`        | 0.025 | —      | — | **REJECTED** (conf 0.02 < 0.25, blast=1) |

**cost_penalty for `rollback_service`:** cost 10/20 = 0.50, downtime 2/10 = 0.20,
blast 1/5 = 0.20 → 0.30·0.50 + 0.30·0.20 + 0.40·0.20 = 0.15 + 0.06 + 0.08 = **0.29**.
**cost_penalty for `increase_pool_size`:** cost 1/20 = 0.05, downtime 0,
blast 1/5 = 0.20 → 0.30·0.05 + 0.40·0.20 = 0.015 + 0.08 = **0.095**.

**Winner:** `increase_pool_size` with **EU = 0.4512**, beating
`rollback_service` (EU = 0.4427) by **0.0085**. The slim margin reflects the
design: confidence is dominant, cost is a moderate tiebreaker. `rollback` has
marginally higher confidence but a much higher cost penalty (0.29 vs 0.095), so
the cheaper action wins.

**page_oncall:** despite zero infrastructure cost, the injected opportunity
cost (0.35, representing ~30 min human MTTR) plus its tiny confidence (0.019)
leave it at EU = 0.017 — correctly never competitive on a well-understood
incident.

---

## 4. When did your engine choose to escalate (page_oncall) instead of auto-act?

My engine escalated on **6 of 8** eval incidents. Crucially, escalation arises
from **three distinct mechanisms**, not one — and only two of the six are
genuine OOD:

| Incident | conf | max_sim | Why it escalated | Correct? |
|----------|------|---------|------------------|----------|
| **E02** | 0.698 | 0.488 | **History says page.** Top match `INC-2025-08-17` (tls_expiry, success) was itself resolved by `page_oncall`, so page collects the votes; all auto-actions fall below the 0.25 blast gate. | TLS rotation is cert-ops, human-only |
| **E04** | 0.136 | 0.136 | **OOD.** `max_similarity 0.136 < 0.25` → forced escalation. | expected accepts page (or dns_config_rollback) |
| **E05** | 0.008 | 0.602 | **Conflict + blast gate.** Not OOD, but top-4 mixes `connection_pool_exhaustion` with `lock_contention` (`INC-2025-07-04`, sim 0.586) → conflict dampening ×0.55 drops every auto-action below 0.25 → only page survives the gate. | expected accepts page (or rollback:payment-svc) |
| **E06** | 0.083 | 0.377 | **Conflict + coherence penalty + blast gate.** Logs say payment-svc (pool exhaustion); dominant trace says `cart-svc → cart-redis`. Coherence penalty + conflict dampening drop the pool-exhaustion actions below the gate. | expected accepts page (or restart:cart-svc) |
| **E07** | 1.000 | 0.426 | **History says page.** Top match `INC-2025-10-15` (infinite_retry, success) was resolved by `page_oncall`; it is the only candidate. *(Not OOD — sim 0.426 is above threshold.)* | expected accepts page only |
| **E08** | 0.052 | 0.052 | **OOD.** `max_similarity 0.052 < 0.25`, zero candidates → forced escalation. | expected accepts page (or rollback:t24-service) |

All six escalations are correct against the eval ground truth.

**Where escalation was correctly avoided:** **E01** (clear pool exhaustion,
conf 0.466 → `increase_pool_size`) and **E03** (clear memory leak, conf 0.987 →
`rollback_service`). Both carry `must_not_action: page_oncall`, so escalating
would have been penalised — the engine auto-acts on both.

**Design note worth flagging:** only **E04** and **E08** trip the explicit OOD
path. E05/E06 escalate because the blast-radius gate (and conflict dampening)
reject every auto-action, and E02/E07 escalate because the matched historical
incident was *itself* resolved by paging. This is the desirable behaviour —
the engine reaches "page" through evidence, not as a blind default — but it
means "escalation" is not synonymous with "novel input" in this engine.

---

## 5. What is the most likely class of incident that breaks your engine?

**Class: incidents with a *known failure pattern* but *novel service
topology*.**

**E08 illustrates it.** It is a 4-service cascade where the true root is the
deepest leaf (`t24-service`), but the services (`t24-service`, `bb-edge`,
`datapower`) never appear in the historical corpus. My engine scores it at
`max_similarity = 0.052` and escalates via the OOD path. That is *acceptable*
(page is an accepted action), but not *ideal*: a smarter engine would
recognise the *shape* — cascade from deep leaf to alerting edge — even when the
service names differ, and could propose `rollback_service:t24-service` (also
accepted).

**Concrete failure scenario.** An `inventory-svc` connection-pool exhaustion
would match the pool-exhaustion log signatures, but every historical
pool-exhaustion entry targets `payment-svc`. The log component (weight 0.40)
would fire, but the trace component (0.35, edge-match) and service Jaccard
(0.25) would both collapse because no historical edge mentions
`inventory-svc`. Similarity would land in the 0.10–0.20 band — right on the
0.25 OOD boundary — and the engine could under-weigh a genuinely known
incident.

**Proposed improvement I did not implement — service-role normalisation.**
Instead of matching service names literally (Jaccard over `affected_services`
and exact edge-match in trace similarity), map each service to its *role* in
the topology (e.g. "api-tier caller", "datastore backend", "edge proxy") and
compute similarity over roles. Then `inventory-svc → catalog-db` would match
`payment-svc → payments-db` because both are "api → store". I did not implement
it because:
1. The corpus is small (29 entries) — role-based matching risks
   over-generalising and would need a larger validation set to tune safely.
2. The current approach already reaches **8/8 accepted, 0 forbidden** on the
   eval set; the marginal value of role normalisation is unverifiable without
   more test incidents.
3. Time budget: extracting roles from topology and rewiring all three
   similarity components (plus the coherence check) is a non-trivial refactor
   of both the feature and retrieval layers.
