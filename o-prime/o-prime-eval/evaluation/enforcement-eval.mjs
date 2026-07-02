/**
 * O-Prime - Enforcement decision test (health + student scenarios)
 *
 * Verifies that enforcement mode blocks only Tier-1 violations (count and
 * temporal), and records (does not block) Tier-2 violations - prohibition,
 * recipient, purpose, legal basis, and duty - using the real engine and
 * loader on the published .ttl policies.
 *
 * Coverage:
 *   - Section A: Health-record scenario (bloodType, MedicalRecord)
 *   - Section B: University/student-record scenario (Person, FinancialAidRecord)
 *   - All 7 policy dimensions tested in both scenarios
 *   - Write-path action prohibitions (DELETE, PUT/update)
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
import { enforcementOutcome } from '../odrl/enforcement.mjs';

const POLDIR = join(dirname(fileURLToPath(import.meta.url)),
  '../../o-prime-extended/policies');
const ttl = (f) => readFileSync(join(POLDIR, f), 'utf-8');

/**
 * Run a scenario against the deployed engine.
 *
 * @param {string} file - Policy file name
 * @param {object} req - Request context
 * @param {object} sotw - State of the World
 * @param {string[]} fields - Accessed RDF predicates
 * @param {string} action - Requested ODRL action
 * @param {string|null} policyId - Specific policy IRI to isolate
 */
const run = (file, req, sotw, fields = [], action = 'ex:read', policyId = null) =>
  runTtl(ttl(file), req, sotw, fields, action, policyId);

const runTtl = (ttlStr, req, sotw, fields = [], action = 'ex:read', policyId = null) => {
  const e = new ODRLPolicyEngine();
  let policies = loadPoliciesFromTurtle(ttlStr);

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
      console.warn(`⚠️ Policy ${policyId} not found, loading all policies`);
    } else {
      policies = filtered;
    }
  }

  e.loadPolicies(policies);
  return e.evaluate(req, sotw, fields, action);
};

// ============================================================================
// INLINE POLICIES (for write-path and edge cases not covered by main files)
// ============================================================================

// Generic prohibition policy for write-path tests
const prohibitPolicy = (act, target = '<https://schema.org/bloodType>') => `
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix ex: <https://example.org/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix report: <https://w3id.org/force/compliance-report#> .
ex:policy-proh a odrl:Policy ;
    odrl:uid <urn:uuid:proh-01> ; dct:title "Write Prohibition" ;
    odrl:target ${target} ;
    report:activationState report:Active ;
    odrl:prohibition ex:proh .
ex:proh odrl:action ${act} .`;

// Student-specific write prohibition (for student scenario write-path tests)
const studentProhibitPolicy = (act) =>
  prohibitPolicy(act, '<https://schema.org/Person>');


// ============================================================================
// TEST CASES
// ============================================================================
// Format: [name, decision, expectBlock]
//   - expectBlock=true  → Tier-1 violation (count/temporal) → BLOCKED in ENFORCE mode
//   - expectBlock=false → Tier-2 violation OR compliant → NOT blocked (recorded only)
// ============================================================================

const CASES = [
  // ############################################################################
  // SECTION A: HEALTH-RECORD SCENARIO
  // ############################################################################

  // ---- Count (T1 - Enforceable) ----
  // Target: schema:bloodType, limit=1
  ['S1  Health count OK (T1)',
    run('count-policy.ttl', {}, { count: { 'schema:bloodType': { count: 0 } } }, ['schema:bloodType'], 'ex:read', 'ex:policy-count-bloodtype'),
    false],
  ['S2  Health count violation (T1)',
    run('count-policy.ttl', {}, { count: { 'schema:bloodType': { count: 2 } } }, ['schema:bloodType'], 'ex:read', 'ex:policy-count-bloodtype'),
    true],

  // ---- Temporal (T1 - Enforceable) ----
  // Target: schema:MedicalRecord, window=2026-01-01 to 2026-12-31
  ['S7  Health temporal OK (T1)',
    run('temporal-policy.ttl', { issued: '2026-06-15T10:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    false],
  ['S8  Health temporal violation - before window (T1)',
    run('temporal-policy.ttl', { issued: '2025-12-31T23:59:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    true],
  ['S9  Health temporal violation - after window (T1)',
    run('temporal-policy.ttl', { issued: '2027-01-05T08:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-temporal-window'),
    true],

  // ---- Purpose (T2 - Accountable, NOT blocked) ----
  // Target: schema:MedicalRecord, permitted=dpv:Healthcare
  ['S3  Health purpose OK (T2)',
    run('purpose-policy.ttl', { purpose: 'dpv:Healthcare' }, { count: {} }, [], 'ex:read', 'ex:policy-purpose-health'),
    false],
  ['S4  Health purpose violation (T2, recorded)',
    run('purpose-policy.ttl', { purpose: 'dpv:Marketing' }, { count: {} }, [], 'ex:read', 'ex:policy-purpose-health'),
    false],

  // ---- Legal Basis (T2 - Accountable, NOT blocked) ----
  // Target: dpv:SpecialCategoryPersonalData, required=dpv:ExplicitConsent
  ['S5  Health legal-basis OK (T2)',
    run('legal-basis-policy.ttl', { legalBasis: 'dpv:ExplicitConsent' }, { count: {} }, [], 'ex:read', 'ex:policy-explicit-consent'),
    false],
  ['S6  Health legal-basis violation (T2, recorded)',
    run('legal-basis-policy.ttl', { legalBasis: 'dpv:LegitimateInterest' }, { count: {} }, [], 'ex:read', 'ex:policy-explicit-consent'),
    false],

  // ---- Recipient (T2 - Accountable, NOT blocked) ----
  // Target: schema:MedicalRecord, approved=HealthcareApp/ClinicalResearchApp
  ['S10 Health recipient OK (T2)',
    run('recipient-policy.ttl', { recipient: 'ex:HealthcareApp' }, { count: {} }, [], 'ex:read', 'ex:policy-recipient'),
    false],
  ['S11 Health recipient violation (T2, recorded)',
    run('recipient-policy.ttl', { recipient: 'ex:UnknownApp' }, { count: {} }, [], 'ex:read', 'ex:policy-recipient'),
    false],

  // ---- Duty (T2 - Accountability, recorded, NOT blocked) ----
  // Target: schema:MedicalRecord, duty=odrl:inform
  ['S12 Health duty (T2, not blocked)',
    run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-duty-notify'),
    false],

  // ---- Prohibition (T2 - Detectable, recorded, NOT blocked) ----
  // Target: schema:MedicalRecord, prohibited=odrl:distribute
  ['S14 Health prohibition distribute (T2, recorded)',
    run('duty-policy.ttl', {}, { count: {} }, [], 'odrl:distribute', 'ex:policy-prohibition-distribute'),
    false],

  // ---- Write-path action prohibitions (recorded, delegated to ACL) ----
  // Note: Inline policies are already isolated, no policyId needed
  ['S-A1 Health DELETE prohibition (recorded)',
    runTtl(prohibitPolicy('odrl:delete'), {}, { count: {} }, [], 'ex:delete'),
    false],
  ['S-A2 Health PUT/update prohibition (recorded)',
    runTtl(prohibitPolicy('odrl:modify'), {}, { count: {} }, [], 'ex:update'),
    false],

  // ############################################################################
  // SECTION B: UNIVERSITY / STUDENT-RECORD SCENARIO
  // ############################################################################

  // ---- Count (T1 - Enforceable) ----
  // Target: schema:Person, limit=3 (more permissive than health-record)
  ['S16 Student count OK - first read (T1)',
    run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 0 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    false],
  ['S17 Student count OK - at limit (T1)',
    run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 3 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    false],
  ['S18 Student count violation (T1)',
    run('count-policy.ttl', {}, { count: { 'schema:Person': { count: 4 } } }, ['schema:Person'], 'ex:read', 'ex:policy-student-count'),
    true],

  // ---- Temporal (T1 - Enforceable) ----
  // Target: schema:Person, window=2026-08-01 to 2027-07-31 (academic year)
  ['S24 Student temporal OK - within academic year (T1)',
    run('temporal-policy.ttl', { issued: '2026-10-15T10:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    false],
  ['S25 Student temporal violation - before academic year (T1)',
    run('temporal-policy.ttl', { issued: '2026-07-31T23:59:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    true],
  ['S26 Student temporal violation - after academic year (T1)',
    run('temporal-policy.ttl', { issued: '2027-08-01T00:00:00Z' }, { count: {} }, [], 'ex:read', 'ex:policy-student-temporal'),
    true],

  // ---- Purpose (T2 - Accountable, NOT blocked) ----
  // Target: schema:Person, permitted=EmploymentVerification/ResearchAndDevelopment
  ['S19 Student purpose OK - EmploymentVerification (T2)',
    run('purpose-policy.ttl', { purpose: 'dpv:EmploymentVerification' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    false],
  ['S20 Student purpose OK - ResearchAndDevelopment (T2)',
    run('purpose-policy.ttl', { purpose: 'dpv:ResearchAndDevelopment' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    false],
  ['S21 Student purpose violation - Marketing (T2, recorded)',
    run('purpose-policy.ttl', { purpose: 'dpv:Marketing' }, { count: {} }, [], 'ex:read', 'ex:policy-student-purpose'),
    false],

  // ---- Legal Basis (T2 - Accountable, NOT blocked) ----
  // Target: dpv:SpecialCategoryPersonalData (financial aid), required=ExplicitConsent
  ['S22 Student legal-basis OK - ExplicitConsent (T2)',
    run('legal-basis-policy.ttl', { legalBasis: 'dpv:ExplicitConsent' }, { count: {} }, [], 'ex:read', 'ex:policy-student-explicit-consent'),
    false],
  ['S23 Student legal-basis violation - Contract (T2, recorded)',
    run('legal-basis-policy.ttl', { legalBasis: 'dpv:Contract' }, { count: {} }, [], 'ex:read', 'ex:policy-student-explicit-consent'),
    false],

  // ---- Recipient (T2 - Accountable, NOT blocked) ----
  // Target: schema:Person, approved=CareerServicesApp/ResearchLabApp
  ['S27 Student recipient OK - CareerServicesApp (T2)',
    run('recipient-policy.ttl', { recipient: 'ex:CareerServicesApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    false],
  ['S28 Student recipient OK - ResearchLabApp (T2)',
    run('recipient-policy.ttl', { recipient: 'ex:ResearchLabApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    false],
  ['S29 Student recipient violation - ExternalEmployerApp (T2, recorded)',
    run('recipient-policy.ttl', { recipient: 'ex:ExternalEmployerApp' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    false],
  ['S30 Student recipient violation - MarketingPlatform (T2, recorded)',
    run('recipient-policy.ttl', { recipient: 'ex:MarketingPlatform' }, { count: {} }, [], 'ex:read', 'ex:policy-student-recipient'),
    false],

  // ---- Duty (T2 - Accountability, recorded, NOT blocked) ----
  // Target: schema:Person, duty=odrl:inform
  ['S31 Student duty (T2, not blocked)',
    run('duty-policy.ttl', {}, { count: {} }, [], 'ex:read', 'ex:policy-student-duty-notify'),
    false],

  // ---- Prohibition (T2 - Detectable, recorded, NOT blocked) ----
  // Target: schema:Person, prohibited=odrl:distribute
  ['S33 Student prohibition distribute (T2, recorded)',
    run('duty-policy.ttl', {}, { count: {} }, [], 'odrl:distribute', 'ex:policy-student-prohibition-distribute'),
    false],

  // ---- Write-path action prohibitions (recorded, delegated to ACL) ----
  // Note: Inline policies are already isolated, no policyId needed
  ['S-B1 Student DELETE prohibition (recorded)',
    runTtl(studentProhibitPolicy('odrl:delete'), {}, { count: {} }, [], 'ex:delete'),
    false],
  ['S-B2 Student PUT/update prohibition (recorded)',
    runTtl(studentProhibitPolicy('odrl:modify'), {}, { count: {} }, [], 'ex:update'),
    false],
];


// ============================================================================
// RUN TESTS
// ============================================================================

let pass = 0;
let healthPass = 0, healthTotal = 0;
let studentPass = 0, studentTotal = 0;

console.log('='.repeat(78));
console.log('O-PRIME - ENFORCEMENT DECISION EVALUATION');
console.log('(deployed engine + real .ttl policies, health + student scenarios)');
console.log('='.repeat(78));
console.log('\nEnforcement decisions (ODRL_ENFORCE=true would block =>):\n');
console.log('─'.repeat(78));

for (const [name, decision, expectBlock] of CASES) {
  const { block, violations } = enforcementOutcome(decision);
  const ok = block === expectBlock;
  pass += ok ? 1 : 0;

  // Track per-scenario stats
  if (name.startsWith('S-A') || (name.match(/^S\d+/) && parseInt(name.match(/^S(\d+)/)[1]) <= 15)) {
    healthTotal++;
    if (ok) healthPass++;
  } else if (name.startsWith('S-B') || (name.match(/^S\d+/) && parseInt(name.match(/^S(\d+)/)[1]) >= 16)) {
    studentTotal++;
    if (ok) studentPass++;
  }

  const status = ok ? '✅ PASS' : '❌ FAIL';
  const blockStr = expectBlock ? 'BLOCK  ' : 'RECORD ';
  const deontic = String(decision.deonticState).padEnd(9);

  console.log(`  ${status} ${name.padEnd(48)} deontic=${deontic} ${blockStr}`);
  if (!ok) {
    console.log(`         Expected block=${expectBlock}, got block=${block}`);
    if (violations?.length > 0) {
      console.log(`         Violations: ${violations.map(v => v.violationType).join(', ')}`);
    }
  }
}

console.log('\n' + '─'.repeat(78));
console.log('SUMMARY BY SCENARIO:');
console.log(`  Health-record  : ${healthPass}/${healthTotal} enforcement decisions correct`);
console.log(`  Student-record : ${studentPass}/${studentTotal} enforcement decisions correct`);
console.log(`  TOTAL          : ${pass}/${CASES.length} enforcement decisions correct`);

console.log('\n' + '─'.repeat(78));
console.log('ENFORCEMENT RULES (per trust model, Section 4.2):');
console.log('  ✅ Tier-1 (BLOCKED in ENFORCE mode):');
console.log('     • odrl:count violations (gateway-controlled counter)');
console.log('     • odrl:dateTime violations (gateway-controlled clock)');
console.log('  ⚠️  Tier-2 (RECORDED, NOT blocked - delegated to ACL):');
console.log('     • odrl:purpose violations (accountability evidence)');
console.log('     • dpv:hasLegalBasis violations (accountability evidence)');
console.log('     • odrl:recipient violations (accountability evidence)');
console.log('     • odrl:duty obligations (accountability evidence)');
console.log('     • odrl:prohibition violations (accountability evidence)');
console.log('='.repeat(78));

process.exit(pass === CASES.length ? 0 : 1);