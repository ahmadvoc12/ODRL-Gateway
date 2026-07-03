# O-Prime - Vocabulary and Reproducibility Artifacts

Supplementary artifacts for **O-Prime: An ODRL-based Privacy Monitoring Framework for
Decentralized Environments** (Journal of Web Semantics). The gateway is in `../o-prime-eval/`;
this package holds the published policies, SHACL shapes, SPARQL competency questions, the DPV
mapping, a sample audit log, and the validation scripts.

## Contents

```
policies/   count-policy.ttl, temporal-policy.ttl, purpose-policy.ttl,
            legal-basis-policy.ttl, recipient-policy.ttl, duty-policy.ttl
shapes/     odrl-policy-shape.ttl   # validates the ODRL policies
            prov-log-shape.ttl      # validates audit-log activities AND the
                                    #   PolicyEvaluation / FieldViolation / PolicyViolation subgraphs
            sotw-state-shape.ttl    # validates the State-of-the-World graph
            dpv-mapping-shape.ttl   # validates the DPV predicate mapping
sparql/     cq1..cq10.rq            # ten competency questions over the audit log
dpv/        dpv-mapping.ttl         # predicate -> DPV category mapping
sotw/       sotw.ttl         # sample State-of-the-World graph
logs/       access-log.ttl   # representative PROV-O audit log
evaluation/ master-evaluation.mjs   # unified engine + listing report
            shacl-validate-real.py  # pyshacl over every artifact in this package
```

## Run

```bash
# SHACL validation over all artifacts (policies, DPV mapping, SoTW, sample log)
python3 evaluation/shacl-validate-real.py        # 9/9 conform, 0 violations

# Unified report (drives the deployed engine on the published policies)
node evaluation/master-evaluation.mjs

# A competency question (rdflib), e.g. CQ3 - which policy governed an access:
python3 -c "from rdflib import Graph; g=Graph().parse('logs/sample-access-log.ttl'); \
print([tuple(map(str,r)) for r in g.query(open('sparql/cq3-policy-for-access.rq').read())])"
```

`shacl-validate-real.py` validates each artifact against the shapes in `shapes/`. The
`prov-log-shape.ttl` constrains both the access activity (PROV-O provenance + the four FORCE
compliance states) and the per-field `PolicyEvaluation`, `FieldViolation`, and
`PolicyViolation` subgraphs emitted in the audit log.

## Competency questions (sparql/)

| CQ | Question |
|---|---|
| CQ1 | Which accesses touched health data? |
| CQ2 | Which accesses violated an ODRL policy? |
| CQ3 | Which policy governed a specific access event? |
| CQ4 | Which accesses occurred without consent? |
| CQ5 | Which accesses violated a temporal constraint? |
| CQ6 | Access history for a given application. |
| CQ7 | Were attached duties fulfilled? |
| CQ8 | Which accesses touched special-category data? |
| CQ9 | Which accesses violated a purpose constraint? |
| CQ10 | Which attributes exceeded their access-count limit? |
