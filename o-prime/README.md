# O-Prime

**An ODRL-based Privacy Monitoring Framework for Decentralized Environments**
(supplementary material for the Journal of Web Semantics submission).

O-Prime is a non-invasive monitoring gateway for Solid Pods. It reverse-proxies HTTP
requests to the Pod server, classifies the accessed and modified predicates with the Data
Privacy Vocabulary (DPV), evaluates ODRL 2.2 policies across seven dimensions (count,
temporal, prohibition, duty, purpose, legal-basis, recipient) against a State-of-the-World
graph, and writes PROV-O audit logs using the ODRL Compliance Report Model. It requires no
modification to the underlying Solid server.

Enforcement model: count and temporal violations are blocked before the request reaches the
backend (their values come from gateway-controlled sources — the usage counter and the
server clock); purpose, legal-basis, recipient, duty and action prohibitions are recorded as
accountability evidence and delegated to the Solid access-control layer.

## Contents

| Path | What it is |
|---|---|
| `o-prime-eval/` | The gateway: `gateway.mjs` + the `odrl/` engine (policy loading, evaluation, enforcement, DPV classification, access counting). Bundles the Community Solid Server, so it runs standalone. |
| `o-prime-extended/` | Vocabulary and reproducibility artifacts: the published ODRL policies, SHACL shapes, SPARQL competency questions, the DPV mapping, a sample audit log, and the validation scripts. |
| `CHANGES.md` | Correctness fixes applied to the baseline gateway, each with its verification. |

## Prerequisites

- **Node.js >= 22** (the gateway bundles `@solid/community-server` and starts it
  automatically).
- **Python 3** with **`pyshacl`** and **`rdflib`** (`pip install pyshacl rdflib`) for SHACL
  validation and the SPARQL competency questions.

## Reproduce

```bash
cd o-prime-eval && npm install        # restores @solid/community-server

# Engine evaluation (no server needed):
node evaluation/policy-eval.mjs        # 15/15 policy scenarios across 7 dimensions
node evaluation/enforcement-eval.mjs   # 10/10 enforcement decisions

# SHACL + competency questions over the artifacts:
python3 ../o-prime-extended/evaluation/shacl-validate-real.py    # 9/9 artifacts conform
node ../o-prime-extended/evaluation/master-evaluation.mjs        # unified report

# Run the gateway (boots CSS on :4000, gateway proxy on :3000):
node gateway.mjs                       # monitoring mode
ODRL_ENFORCE=true node gateway.mjs     # enforcement mode (blocks count + temporal)
```

## Results at a glance

| Check | Result |
|---|---|
| Policy-engine scenarios (7 dimensions) | 15/15 |
| Enforcement decisions | 10/10 |
| SHACL conformance (policies, shapes, DPV mapping, SoTW, sample log) | 9/9, 0 violations |
| Authored deployed policy | all seven dimensions load and reach the engine |
| Count/temporal enforcement on writes | blocked (403) before backend at the limit |

## Directory structure

```
o-prime-eval/
  gateway.mjs                 # the monitoring gateway
  odrl/                       # policy-loader, policy-engine, enforcement, request-builder,
                              #   context-provider, access-counter, compliance-reporter
  evaluation/                 # policy-eval.mjs, enforcement-eval.mjs (engine checks)
o-prime-extended/
  policies/   *.ttl           # published per-dimension ODRL policies
  shapes/     *.ttl           # SHACL shapes (odrl-policy, prov-log, sotw-state, dpv-mapping)
  sparql/     cq1..cq10.rq    # competency questions
  dpv/        dpv-mapping.ttl # DPV predicate mapping
  sotw/       sotw.ttl # sample State-of-the-World graph
  logs/       access-log.ttl  # representative PROV-O audit log
  evaluation/ master-evaluation.mjs, shacl-validate-real.py
```

## Citation

```
Isnaini, U., Adi, A.C., Hanif, M., Kurniawan, K., & Ekelhart, A. (2026).
O-Prime: An ODRL-based Privacy Monitoring Framework for Decentralized Environments.
Journal of Web Semantics.
```
