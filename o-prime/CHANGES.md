# Correctness fixes over the baseline

This version is the original O-Prime gateway with three correctness defects fixed.
No evaluation scaffolding, scenarios, or alternative engines were added; the changes
are confined to `o-prime-eval/gateway.mjs` and `o-prime-eval/odrl/access-counter.mjs`.

## 1. Malformed agent IRI in the audit log (`gateway.mjs`)
The `prov:wasAssociatedWith` agent term was built by unconditionally prefixing the
value with `ex:`. A CURIE such as `ex:HealthcareApp` became `ex:ex_HealthcareApp`, and a
`client_id` URL became `ex:https___...`. This produced malformed agent identifiers in
every log and broke agent-access-history queries. Replaced with `agentTerm()`, which
emits a single well-formed term: an absolute IRI/URN is wrapped in `<...>`, a CURIE with
a declared prefix is kept as-is, and a bare token becomes `ex:<sanitised>`.

## 2. Write-path count never accumulated (`gateway.mjs`, `access-counter.mjs`)
The write path (POST/PUT/PATCH/DELETE) evaluated policies but never incremented the
access counter and never updated the State-of-the-World. Count-based limits therefore
did not accumulate over writes, so an exceeded write count was never detected or blocked.
The write path now increments the per-field counter and updates the SoTW before/after
evaluation, mirroring the read path. The access counter key now includes the ODRL action,
so read and write counts on the same field stay independent.

## 3. No DPV classification on writes (`gateway.mjs`)
The write path logged `personalData: null`, so modified fields were action-evaluated but
never classified with DPV. It now classifies the request body via `extractPersonalData`,
matching the read path.

## 4. Policy parser dropped named-blank-node permissions (`gateway.mjs`)
`parsePolicyMetadata` extracted permission actions only from inline `odrl:permission
[ ... ]` blocks. The deployed `monitor-policy.ttl` correctly scopes the identifier count
constraint to both `ex:read` and `ex:update` using two *named* blank-node permissions
(`odrl:permission _:p-read, _:p-update`), which the regex did not match — so the parser
fell back to its `['ex:read']` default and silently loaded the count policy as read-only.
The engine then skipped the count constraint on any write action (`_actionMatches`
filters the permission out), making fix #2 inert for enforcement. The parser now also
resolves named/blank-node permission references and reads their `odrl:action` (mirroring
the existing prohibition resolution), so the engine honours the write scope the policy
actually declares. This is the change that makes count enforcement on writes effective.

## 5. Gateway runtime loaded only count + prohibition from deployed policies (`gateway.mjs`)
The gateway's runtime loader (`parsePolicyMetadata` + `loadPolicies`) built a hardcoded
`leftOperand:"odrl:count"` constraint (with a `maxCount:3` default) from every deployed
policy block and never parsed `dateTime`/`purpose`/`hasLegalBasis`/`recipient`/`duty`. So a
pod owner authoring any non-count constraint in a deployed `.ttl` had it silently dropped —
and a non-count policy was even replaced by a spurious `count <= 3` rule. (The full
seven-dimension ODRL parser `odrl/policy-loader.mjs` existed but was used only by the
offline evaluation scripts, not the live gateway.)

`loadPolicies` now routes deployed-policy parsing through `loadPoliciesFromTurtle` (the
shared RDF loader), so all seven dimensions load from the authored `.ttl` and reach the
engine. A small adapter preserves the gateway-specific needs the full loader does not
carry: `force:policyActive` de-activation and the `dct:identifier` (via a light
`parsePolicyMetadata` pass), policy keying by `protectedByPolicy` for audit-log lookups,
and `activePolicyIRIs`. The hardcoded count constraint and the `maxCount:3` default
injection are removed, so an authored non-count policy is no longer turned into a count
rule. Count enforcement on writes (fix #2/#4) is preserved — the count limit now comes
from the authored `odrl:count` constraint, and named/blank-node write-action scoping is
resolved natively by the RDF loader. The engine evaluation logic and `ENFORCED_OPERANDS`
were not changed.

## 6. Audit-log count-detail logged a wrong/absent limit (`gateway.mjs`, logging only)
The audit-log count-violation detail read the limit as
`pol?.permission?.constraint?.rightOperand || 3`. For a multi-permission policy (the full
loader emits an array of permission rules) `pol.permission.constraint` is `undefined`, so
the limit defaulted to 3; and the policy itself was looked up by `getPolicy(protectedByPolicy)`,
which does not resolve for authored/full-loader policies (they key by resource and store
`targetIRI` as a CURIE), so the detail entry was often not emitted at all. Added two
logging-only helpers: `countLimitFor(pol, action)` resolves the `odrl:count` limit from the
permission whose action the engine actually evaluated (handles array permissions and
AND-compound constraints, returns null instead of defaulting), and `policyForField` resolves
the policy by target match when the `protectedByPolicy` key misses. The same resolver is
also applied to the per-field `PolicyEvaluation` context subgraph (which records, for each
accessed field, the policy evaluated, the result, the reason, and the target asset) — it
was previously skipped entirely for authored/full-loader policies for the same key-miss
reason, silently omitting "which policy was evaluated" from the audit log. The engine,
enforcement, `ENFORCED_OPERANDS`, and the loader were NOT changed; the 403/block decision is unchanged.
Verified: a multi-permission policy (read `lteq 5`, update `lteq 2`) now logs
`allowedLimit "2"` for an exceeded write (the evaluated permission), a single-permission
policy logs its actual limit, and count blocking + engine gates are unchanged.

## 7. SHACL shapes for the audit-log compliance subgraphs (`o-prime-extended/shapes`, shapes only)
`prov-log-shape.ttl` previously targeted only `prov:Activity`, so the
`report:PolicyEvaluation`, `report:FieldViolation`, and `report:PolicyViolation` subgraphs
were emitted but never validated (they passed SHACL trivially). Added three `sh:NodeShape`
definitions targeting those classes, constraining only the predicates the emitter produces
on every instance (verified against real output + `logs/sample-access-log.ttl`):
PolicyEvaluation -> `evaluatedPolicy` (IRI), `evaluationResult` (`ALLOWED`|`VIOLATION`),
`evaluationReason`, `targetAsset` (IRI); FieldViolation -> `violatedField` (IRI),
`observedCount`/`allowedLimit` (`xsd:integer`), `actionType`; PolicyViolation ->
`violationType`, `violationTimestamp` (`xsd:dateTime`), `violatedPolicy` (IRI), and
`hasFieldViolation` typed to `FieldViolation` when present (optional - only count violations
carry it). No emitter/engine/enforcement change. Note vs. the original assumption:
FieldViolation carries `actionType`, not `violationType` (which is on PolicyViolation), and
`hasFieldViolation` is not required. Verified: real compliant + violation logs conform (0
violations); the master validator stays 9/9 (sample log conforms); and the shapes bite - a
FieldViolation missing `allowedLimit`, a PolicyEvaluation missing `evaluatedPolicy`, and a
bad `evaluationResult` enum each raise a SHACL violation.

## Verification
- `node o-prime-eval/evaluation/policy-eval.mjs` — 15/15 engine scenarios.
- `node o-prime-eval/evaluation/enforcement-eval.mjs` — 10/10 enforcement decisions.
- Counter unit check: read and write counts on the same field remain independent.
- Live enforcement (ODRL_ENFORCE=true): PUTs to a count-limited writable attribute
  (`schema:identifier`, `lteq 3`) increment the write counter (1,2,3,...) and are BLOCKED
  with HTTP 403 (`X-ODRL-Decision: BLOCKED`) before the backend once the count exceeds the
  limit; the read counter for the same field is a separate key (independence).
- SHACL (`prov-log-shape`) over the regenerated log, including write DPV bundles: conforms.
- CQ6 over the generated log: non-empty for 2 agents; agent IRIs single-prefixed/well-formed.
- Full-loader routing (fix #5): authored deployed `.ttl` policies for all seven dimensions
  load and reach the engine. Verified live — authored temporal: out-of-window PUT 403
  `BLOCKED` before backend, in-window not blocked; authored purpose/legal-basis/recipient:
  constraint violations recorded; authored duty: obligation recorded; purpose-only policy:
  no spurious count rule (no count block across repeated writes); count blocking-write and
  engine gates (15/15, 10/10) unchanged.
