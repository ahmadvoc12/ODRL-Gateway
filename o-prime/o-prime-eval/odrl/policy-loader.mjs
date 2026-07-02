/**
 * O-Prime ODRL Policy Loader
 *
 * Parses ODRL 2.2 Turtle policy documents into the plain-object form consumed
 * by ODRLPolicyEngine (policy-engine.mjs). This is a REAL RDF loader (N3),
 * not a regex extractor: it resolves named and blank-node permissions,
 * prohibitions, duties and constraints, and supports all seven constraint
 * types (count, purpose, legal-basis, temporal, recipient, duty, prohibition).
 *
 * It is the single policy-loading path shared by the gateway and the
 * reproducible evaluation harness, so both drive the same engine with the
 * same policies parsed from the same .ttl files.
 */
import { Parser, Store, DataFactory } from 'n3';

const { namedNode } = DataFactory;

const ODRL = 'http://www.w3.org/ns/odrl/2/';
const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const DCT = 'http://purl.org/dc/terms/';
const REPORT = 'https://w3id.org/force/compliance-report#';

// IRI -> CURIE prefixes the engine switches on (must match policy-engine.mjs).
const PREFIXES = [
  [ODRL, 'odrl:'],
  ['https://w3id.org/dpv#', 'dpv:'],
  ['https://example.org/', 'ex:'],
  ['https://schema.org/', 'schema:'],
  ['http://www.w3.org/2001/XMLSchema#', 'xsd:'],
  [REPORT, 'report:'],
  [DCT, 'dct:'],
];

function curie(iri) {
  for (const [base, p] of PREFIXES) {
    if (iri.startsWith(base)) return p + iri.slice(base.length);
  }
  return iri;
}

/** Term -> engine value: IRIs become CURIEs, literals keep their lexical value. */
function termValue(term) {
  return term.termType === 'Literal' ? term.value : curie(term.value);
}

export function loadPoliciesFromTurtle(ttl) {
  const store = new Store(new Parser().parse(ttl));
  const policies = {};

  const objs = (s, p) =>
    store.getObjects(s, namedNode(p), null);
  const obj = (s, p) => objs(s, p)[0] || null;

  // Resolve a constraint node -> { leftOperand, operator, rightOperand }
  const readConstraint = (node) => {
    const left = obj(node, ODRL + 'leftOperand');
    const op = obj(node, ODRL + 'operator');
    const rights = objs(node, ODRL + 'rightOperand');
    if (!left || !op) return null;
    const rightVals = rights.map(termValue);
    return {
      leftOperand: curie(left.value),
      operator: curie(op.value),
      rightOperand: rightVals.length > 1 ? rightVals : rightVals[0],
    };
  };

  const readConstraints = (ruleNode) => {
    const cs = objs(ruleNode, ODRL + 'constraint')
      .map(readConstraint)
      .filter(Boolean);
    return cs.length === 0 ? null : cs.length === 1 ? cs[0] : cs;
  };

  const readActions = (ruleNode) =>
    objs(ruleNode, ODRL + 'action').map((t) => curie(t.value));

  const readDuties = (ruleNode) =>
    objs(ruleNode, ODRL + 'duty').map((d) => ({
      action: curie((obj(d, ODRL + 'action') || namedNode('')).value) || null,
      target: (obj(d, ODRL + 'target') || {}).value
        ? curie(obj(d, ODRL + 'target').value)
        : null,
    }));

  const readRule = (node) => {
    const rule = {};
    const actions = readActions(node);
    if (actions.length) rule.actions = actions;
    const constraint = readConstraints(node);
    if (constraint) rule.constraint = constraint;
    const duties = readDuties(node);
    if (duties.length) rule.duty = duties;
    return rule;
  };

  // Each subject typed odrl:Policy
  const policyNodes = store
    .getSubjects(namedNode(RDF + 'type'), namedNode(ODRL + 'Policy'), null);

  for (const pNode of policyNodes) {
    // Skip non-active policies (report:activationState != report:Active)
    const act = obj(pNode, REPORT + 'activationState');
    if (act && curie(act.value) !== 'report:Active') continue;

    const uid = (obj(pNode, ODRL + 'uid') || {}).value || pNode.value;
    const title = (obj(pNode, DCT + 'title') || {}).value || pNode.value;
    const target = obj(pNode, ODRL + 'target');

    const permissions = objs(pNode, ODRL + 'permission').map(readRule);
    const prohibitions = objs(pNode, ODRL + 'prohibition').map(readRule);
    const topDuties = readDuties(pNode);

    const policy = {
      uid,
      resource: curie(pNode.value),
      title,
      targetIRI: target ? curie(target.value) : null,
      active: true,
    };
    if (permissions.length)
      policy.permission = permissions.length === 1 ? permissions[0] : permissions;
    if (prohibitions.length)
      policy.prohibition =
        prohibitions.length === 1 ? prohibitions[0] : prohibitions;
    if (topDuties.length) policy.duty = topDuties;

    policies[curie(pNode.value)] = policy;
  }

  return policies;
}

export default loadPoliciesFromTurtle;
