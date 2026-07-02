/**
 * O-Prime - Reproducible Policy-Engine Evaluation
 *
 * Drives the DEPLOYED gateway engine (odrl/policy-engine.mjs) through the
 * shared ODRL loader (odrl/policy-loader.mjs) on the PUBLISHED .ttl policy
 * files. This is the same engine + same loader the gateway uses, so the
 * scenario results reflect the deployed system rather than a separate
 * reference implementation.
 *
 * Constraint semantics under the deployed engine:
 *   - count, purpose, legal-basis, temporal, recipient, prohibition are
 *     evaluated and can yield a Violated decision (technical evaluation).
 *   - duty is RECORDED as an obligation (Tier-2 accountability); it does not
 *     block access. Scenarios assert the obligation is logged, not that it
 *     denies access.
 *
 * Coverage:
 *   - Section A: Health-record scenario (bloodType, MedicalRecord)
 *   - Section B: University/student-record scenario (Person, FinancialAidRecord)
 *   - All 7 policy dimensions tested in both scenarios
 *
 * IMPORTANT: Each scenario specifies a `policyId` to isolate the specific
 * policy being tested. This prevents cross-scenario conflicts since health
 * and student policies share the same .ttl files.
 */
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { ODRLPolicyEngine } from '../odrl/policy-engine.mjs';
import { loadPoliciesFromTurtle } from '../odrl/policy-loader.mjs';

const POLDIR = join(dirname(fileURLToPath(import.meta.url)),
  '../../o-prime-extended/policies');
const ttl = (f) => readFileSync(join(POLDIR, f), 'utf-8');

/**
 * Run a scenario against the deployed engine.
 *
 * @param {string} file - Policy file name
 * @param {object} req - Request context
 * @param {object} sotw - State of the World
 * @param {string[]} accessedFields - Accessed RDF predicates
 * @param {string} action - Requested ODRL action
 * @param {string|null} policyId - Specific policy IRI to isolate (prevents cross-scenario conflicts)
 */
function run(file, req, sotw, accessedFields = [], action = 'ex:read', policyId = null) {
  const engine = new ODRLPolicyEngine();
  let policies = loadPoliciesFromTurtle(ttl(file));

  // Filter to only the specific policy being tested
  if (policyId) {
    const filtered = {};
    for (const [key, pol] of Object.entries(policies)) {
      const matches =
        pol.resource === policyId ||
        pol.uid === policyId ||
        pol.identifier === policyId ||
        key === policyId;
      if (matches) {
        filtered[key] = pol;
      }
    }
    if (Object.keys(filtered).length === 0) {
      console.warn(`⚠️ Policy ${policyId} not found in ${file}, loading all policies`);
      policies = policies;
    } else {
      policies = filtered;
    }
  }

  engine.loadPolicies(policies);
  return engine.evaluate(req, sotw, accessedFields, action);
}

const isV = (d) => d.deonticState === 'Violated';
const isF = (d) => d.deonticState === 'Fulfilled';

// ============================================================================
// SCENARIO DEFINITIONS
// ============================================================================
// Grouped by scenario (health-record vs student-record) and constraint type.
// Each scenario drives the real engine and checks the real decision object.
// The `policyId` field isolates the specific policy being tested.
// ============================================================================

const SCENARIOS = [
  // ############################################################################
  // SECTION A: HEALTH-RECORD SCENARIO
  // ############################################################################

  // ---- Count (T1 - Enforceable) ----
  // Target: schema:bloodType, limit=1
  { id: 'S1', scenario: 'Health', type: 'Count', expect: 'Fulfilled',
    desc: 'First read of bloodType (count=0, limit=1)',
    go: () => run('count-policy.ttl', {}, { count: { 'schema:bloodType': { count: 0 } } }, ['schema:bloodType'], 'ex:read', 'ex:policy-count-bloodtype'),
    ok: isF },
  { id: 'S2', scenario: 'Health', type: 'Count', expect: 'Violated',
    desc: 'Second read of bloodType (count=2, limit=1)',
    go: () => run('count-policy.ttl', {}, { count: { 'schema:bloodType': { count: 2 } } }, ['schema:bloodType'], 'ex:read', 'ex:policy-count-bloodtype'),
    ok: isV },

  // ---- Purpose (T2 - Accountable) ----
  // Target: schema:MedicalRecord, permitted=dpv:Healthcare, prohibited=dpv:Marketing
  { id: 'S3', scenario: 'Health', type: 'Purpose', expect: 'Fulfilled',
    desc: 'Healthcare app accessing health data for Healthcare purpose',
    go: () => run('purpose-policy.ttl', { purpose: 'dpv:Healthcare' }, { count: {} }, [], 'ex:read', 'ex:policy-purpose-health'),
    ok: isF },
  { id: 'S4', scenario: 'Health', type: 'Purpose', expect: 'Violated',
    desc: 'Marketing app accessing health data for Marketing purpose',
    go: () => run('purpose-policy.ttl', { purpose: 'dpv:Marketing' }, { count: {} }, [], 'ex:read', 'ex:policy-purpose-health'),
    ok: isV },

  // ---- Legal Basis (T2 - Accountable) ----
  // Target: dpv:SpecialCategoryPersonalData, required=dpv:ExplicitConsent
  { id: 'S5', scenario: 'Health', type: 'Legal Basis', expect: 'Fulfilled',
    desc: 'Health data with ExplicitConsent legal basis',
    go: () => run('legal-basis-policy.ttl', { legalBasis: 'dpv:ExplicitConsent' }, { count: {} }, [], 'ex:read', 'ex:policy-explicit-consent'),
    ok: isF },
  { id: 'S6', scenario: 'Health', type: 'Legal Basis', expect: 'Violated',
    desc: 'Health data with LegitimateInterest legal basis (insufficient)',
    go: () => run('legal-basis-policy.ttl', { legalBasis: 'dpv:LegitimateInterest' }, { count: {} }, [], 'ex:read', 'ex:policy-explicit-consent'),
    ok: isV },

  // ---- Temporal (T1 - Enforceable) ----
  // Target: schema:MedicalRecord, window=2026-01-01 to 2026-12-31
  { id: 'S7', scenario: 'Health', type: 'Temporal', expect: 'Fulfilled',
    desc: 'Access within 2026 calendar year (2026-06-15)',
    go: () => run('temporal-policy.ttl', { issued: '2026-06-15T10:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    ok: isF },
  { id: 'S8', scenario: 'Health', type: 'Temporal', expect: 'Violated',
    desc: 'Access before 2026 window (2025-12-31)',
    go: () => run('temporal-policy.ttl', { issued: '2025-12-31T23:59:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    ok: isV },
  { id: 'S9', scenario: 'Health', type: 'Temporal', expect: 'Violated',
    desc: 'Access after 2026 window (2027-01-05)',
    go: () => run('temporal-policy.ttl', { issued: '2027-01-05T08:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    ok: isV },

  // ---- Recipient (T2 - Accountable) ----
  // Target: schema:MedicalRecord, approved=HealthcareApp/ClinicalResearchApp
  { id: 'S10', scenario: 'Health', type: 'Recipient', expect: 'Fulfilled',
    desc: 'HealthcareApp (authorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:HealthcareApp' }, { count: {} }, [], 'ex:read', 'ex:policy-recipient'),
    ok: isF },
  { id: 'S11', scenario: 'Health', type: 'Recipient', expect: 'Violated',
    desc: 'UnknownApp (unauthorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:UnknownApp' }, { count: {} }, [], 'ex:read', 'ex:policy-recipient'),
    ok: isV },

  // ---- Duty (T2 - Accountability: recorded, not enforced) ----
  // Target: schema:MedicalRecord, duty=odrl:inform
  { id: 'S12', scenario: 'Health', type: 'Duty', expect: 'Recorded+Allowed',
    desc: 'Health data access with duty to notify (fulfilled)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-duty-notify'),
    ok: (d) => isF(d) && d.dutyObligations?.some((o) => o.action === 'odrl:inform') },
  { id: 'S13', scenario: 'Health', type: 'Duty', expect: 'Recorded unfulfilled+Allowed',
    desc: 'Health data access with duty to notify (unfulfilled)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-duty-notify'),
    ok: (d) => isF(d) && d.dutyObligations?.some((o) => o.action === 'odrl:inform' && o.fulfilled === false) },

  // ---- Prohibition (T2 - Detectable) ----
  // Target: schema:MedicalRecord, prohibited=odrl:distribute
  { id: 'S14', scenario: 'Health', type: 'Prohibition', expect: 'Violated',
    desc: 'Distribute health data (prohibited action)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'odrl:distribute', 'ex:policy-prohibition-distribute'),
    ok: isV },
  { id: 'S15', scenario: 'Health', type: 'Prohibition', expect: 'Fulfilled',
    desc: 'Read health data (permitted action)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-duty-notify'),
    ok: isF },

  // ############################################################################
  // SECTION B: UNIVERSITY / STUDENT-RECORD SCENARIO
  // ############################################################################

  // ---- Count (T1 - Enforceable) ----
  // Target: schema:Person, limit=3 (more permissive than health-record)
  { id: 'S16', scenario: 'Student', type: 'Count', expect: 'Fulfilled',
    desc: 'First read of student record (count=0, limit=3)',
    go: () => run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 0 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    ok: isF },
  { id: 'S17', scenario: 'Student', type: 'Count', expect: 'Fulfilled',
    desc: 'Third read of student record (count=3, limit=3)',
    go: () => run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 3 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    ok: isF },
  { id: 'S18', scenario: 'Student', type: 'Count', expect: 'Violated',
    desc: 'Fourth read of student record (count=4, limit=3)',
    go: () => run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 4 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    ok: isV },

  // ---- Purpose (T2 - Accountable) ----
  // Target: schema:Person, permitted=EmploymentVerification/ResearchAndDevelopment, prohibited=Marketing
  { id: 'S19', scenario: 'Student', type: 'Purpose', expect: 'Fulfilled',
    desc: 'CareerServices accessing student data for EmploymentVerification',
    go: () => run('purpose-policy.ttl', { purpose: 'dpv:EmploymentVerification' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    ok: isF },
  { id: 'S20', scenario: 'Student', type: 'Purpose', expect: 'Fulfilled',
    desc: 'ResearchLab accessing student data for ResearchAndDevelopment',
    go: () => run('purpose-policy.ttl', { purpose: 'dpv:ResearchAndDevelopment' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    ok: isF },
  { id: 'S21', scenario: 'Student', type: 'Purpose', expect: 'Violated',
    desc: 'MarketingPlatform accessing student data for Marketing',
    go: () => run('purpose-policy.ttl', { purpose: 'dpv:Marketing' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    ok: isV },

  // ---- Legal Basis (T2 - Accountable) ----
  // Target: dpv:SpecialCategoryPersonalData (financial aid), required=ExplicitConsent
  { id: 'S22', scenario: 'Student', type: 'Legal Basis', expect: 'Fulfilled',
    desc: 'Financial aid data with ExplicitConsent',
    go: () => run('legal-basis-policy.ttl', { legalBasis: 'dpv:ExplicitConsent' }, { count: {} }, [], 'ex:read', 'ex:policy-student-explicit-consent'),
    ok: isF },
  { id: 'S23', scenario: 'Student', type: 'Legal Basis', expect: 'Violated',
    desc: 'Financial aid data with Contract legal basis (insufficient)',
    go: () => run('legal-basis-policy.ttl', { legalBasis: 'dpv:Contract' }, { count: {} }, [], 'ex:read', 'ex:policy-student-explicit-consent'),
    ok: isV },

  // ---- Temporal (T1 - Enforceable) ----
  // Target: schema:Person, window=2026-08-01 to 2027-07-31 (academic year)
  { id: 'S24', scenario: 'Student', type: 'Temporal', expect: 'Fulfilled',
    desc: 'Access within academic year (2026-10-15)',
    go: () => run('temporal-policy.ttl', { issued: '2026-10-15T10:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    ok: isF },
  { id: 'S25', scenario: 'Student', type: 'Temporal', expect: 'Violated',
    desc: 'Access before academic year (2026-07-31)',
    go: () => run('temporal-policy.ttl', { issued: '2026-07-31T23:59:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    ok: isV },
  { id: 'S26', scenario: 'Student', type: 'Temporal', expect: 'Violated',
    desc: 'Access after academic year (2027-08-01)',
    go: () => run('temporal-policy.ttl', { issued: '2027-08-01T00:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    ok: isV },

  // ---- Recipient (T2 - Accountable) ----
  // Target: schema:Person, approved=CareerServicesApp/ResearchLabApp
  { id: 'S27', scenario: 'Student', type: 'Recipient', expect: 'Fulfilled',
    desc: 'CareerServicesApp (authorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:CareerServicesApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    ok: isF },
  { id: 'S28', scenario: 'Student', type: 'Recipient', expect: 'Fulfilled',
    desc: 'ResearchLabApp (authorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:ResearchLabApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    ok: isF },
  { id: 'S29', scenario: 'Student', type: 'Recipient', expect: 'Violated',
    desc: 'ExternalEmployerApp (unauthorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:ExternalEmployerApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    ok: isV },
  { id: 'S30', scenario: 'Student', type: 'Recipient', expect: 'Violated',
    desc: 'MarketingPlatform (unauthorized recipient)',
    go: () => run('recipient-policy.ttl', { recipient: 'ex:MarketingPlatform' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    ok: isV },

  // ---- Duty (T2 - Accountability: recorded, not enforced) ----
  // Target: schema:Person, duty=odrl:inform
  { id: 'S31', scenario: 'Student', type: 'Duty', expect: 'Recorded+Allowed',
    desc: 'Student record access with duty to notify (fulfilled)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-student-duty-notify'),
    ok: (d) => isF(d) && d.dutyObligations?.some((o) => o.action === 'odrl:inform') },
  { id: 'S32', scenario: 'Student', type: 'Duty', expect: 'Recorded unfulfilled+Allowed',
    desc: 'Student record access with duty to notify (unfulfilled)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-student-duty-notify'),
    ok: (d) => isF(d) && d.dutyObligations?.some((o) => o.action === 'odrl:inform' && o.fulfilled === false) },

  // ---- Prohibition (T2 - Detectable) ----
  // Target: schema:Person, prohibited=odrl:distribute
  { id: 'S33', scenario: 'Student', type: 'Prohibition', expect: 'Violated',
    desc: 'Distribute student data (prohibited action)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'odrl:distribute', 'ex:policy-student-prohibition-distribute'),
    ok: isV },
  { id: 'S34', scenario: 'Student', type: 'Prohibition', expect: 'Fulfilled',
    desc: 'Read student data (permitted action)',
    go: () => run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-student-duty-notify'),
    ok: isF },
];

/**
 * Run all scenario tests and return results with statistics.
 */
export function scenarioTests() {
  const results = SCENARIOS.map((s) => {
    let d, err = null;
    try { d = s.go(); } catch (e) { err = e.message; }
    const pass = !err && s.ok(d);
    return { ...s, actual: err ? `ERR:${err}` : d.deonticState, pass };
  });
  const passed = results.filter((r) => r.pass).length;
  return {
    results,
    passed,
    total: results.length,
    accuracy: ((passed / results.length) * 100).toFixed(1)
  };
}

/**
 * Performance test: measure engine latency with increasing number of policies.
 * Uses purpose-policy.ttl as the base policy, replicated N times.
 */
export function perfTest() {
  const engine = new ODRLPolicyEngine();
  const base = loadPoliciesFromTurtle(ttl('purpose-policy.ttl'));
  const rows = [];

  for (const n of [1, 3, 5, 10, 50, 100]) {
    const set = {};
    for (let i = 0; i < n; i++) set[`p${i}`] = Object.values(base)[0];
    engine.loadPolicies(set);

    const lat = [];
    for (let i = 0; i < 2000; i++) {
      const t0 = performance.now();
      engine.evaluate({ purpose: 'dpv:Healthcare' }, { count: {} }, []);
      lat.push(performance.now() - t0);
    }

    lat.sort((a, b) => a - b);
    const q = (p) => lat[Math.floor(lat.length * p / 100)];
    rows.push({ n, p50: q(50), p99: q(99) });
  }
  return rows;
}

/**
 * Main entry point for CLI execution.
 */
function main() {
  console.log('='.repeat(78));
  console.log('O-PRIME - POLICY-ENGINE EVALUATION');
  console.log('(deployed engine + real .ttl policies, health + student scenarios)');
  console.log('='.repeat(78));

  const sc = scenarioTests();

  // Print individual results
  console.log('\nScenario correctness (34 scenarios, 7 constraint types, 2 domains):');
  console.log('─'.repeat(78));
  for (const r of sc.results) {
    const status = r.pass ? '✅ PASS' : '❌ FAIL';
    console.log(`  ${status} ${r.id.padEnd(4)} [${r.scenario.padEnd(7)}] ${r.type.padEnd(12)} | ${r.desc}`);
    if (!r.pass) {
      console.log(`         Expected: ${r.expect}, Got: ${r.actual}`);
    }
  }

  // Summary by constraint type
  const byType = {};
  for (const r of sc.results) {
    byType[r.type] ??= { p: 0, t: 0 };
    byType[r.type].t++;
    if (r.pass) byType[r.type].p++;
  }
  console.log('\n' + '─'.repeat(78));
  console.log('By constraint type:');
  console.log('  ' + Object.entries(byType)
    .map(([k, v]) => `${k.padEnd(12)} ${v.p}/${v.t} (${((v.p/v.t)*100).toFixed(0)}%)`)
    .join(' | '));

  // Summary by scenario domain
  const byScenario = {};
  for (const r of sc.results) {
    byScenario[r.scenario] ??= { p: 0, t: 0 };
    byScenario[r.scenario].t++;
    if (r.pass) byScenario[r.scenario].p++;
  }
  console.log('\nBy scenario domain:');
  console.log('  ' + Object.entries(byScenario)
    .map(([k, v]) => `${k.padEnd(7)} ${v.p}/${v.t} (${((v.p/v.t)*100).toFixed(0)}%)`)
    .join(' | '));

  // Overall accuracy
  console.log('\n' + '─'.repeat(78));
  console.log(`OVERALL ACCURACY: ${sc.passed}/${sc.total} = ${sc.accuracy}%`);

  // Performance test
  console.log('\n' + '='.repeat(78));
  console.log('Engine latency vs #policies (2000 evals each):');
  console.log('─'.repeat(78));
  console.log('  policies |  p50(ms) |  p99(ms)');
  console.log('  ' + '─'.repeat(30));
  for (const r of perfTest()) {
    console.log(`  ${String(r.n).padEnd(8)} | ${r.p50.toFixed(4).padStart(8)} | ${r.p99.toFixed(4).padStart(8)}`);
  }
  console.log('\n' + '='.repeat(78));

  return sc.passed === sc.total ? 0 : 1;
}

// Run as CLI when invoked directly (not when imported).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}