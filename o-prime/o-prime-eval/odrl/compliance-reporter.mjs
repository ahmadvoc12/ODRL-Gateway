/**
 * Compliance Reporter
 * Generate compliance reports per the paper (report: namespace)
 * For logging access attempts and violations
 */

export class ComplianceReporter {

  /**
   * Render a rule reference (the policy/rule a report is about) as a valid
   * Turtle term. Accepts CURIEs (ex:foo), URNs/URIs, or bare slugs.
   */
  ruleRef(ref) {
    if (!ref) return 'ex:monitor-policy';
    const s = String(ref).trim();
    if (s.startsWith('urn:') || s.startsWith('http://') || s.startsWith('https://')) return `<${s}>`;
    if (s.startsWith('<') || /^[A-Za-z][\w-]*:[\w./#-]+$/.test(s)) return s; // already a term/CURIE
    return `ex:${s.replace(/[^A-Za-z0-9_-]/g, '_')}`;
  }

  /**
   * ODRL Compliance Report Model state triples for an evaluated access,
   * derived from the live decision. Returned as predicate-object strings to
   * be merged into the access record's prov:Activity. This is the single
   * place that maps an engine decision onto report:* deontic states.
   *
   * @param {Object} decision - engine decision ({permitted, matchedPolicies,...})
   * @returns {string[]} predicate-object fragments (no trailing punctuation)
   */
  complianceReportTriples(decision) {
    const permitted = !!decision.permitted;
    const rule = this.ruleRef(decision.matchedPolicies?.[0]
      || decision.violatedConstraints?.[0]?.constraint?.uid);
    return [
      `report:rule ${rule}`,
      `report:activationState report:Active`,
      `report:attemptState report:Attempted`,
      `report:performanceState ${permitted ? 'report:Performed' : 'report:NotPerformed'}`,
      `report:deonticState ${permitted ? 'report:Fulfilled' : 'report:Violated'}`,
    ];
  }

  /**
   * Generate a compliance report for an access attempt
   * @param {Object} params - Report parameters
   * @returns {string} Turtle representation
   */
  generateAccessReport({
    pod,
    evalRequest,
    decision,
    accessedFields,
    violationType = null
  }) {
    const reportId = `report-${Date.now()}`;
    const accessId = `access-${Date.now()}`;
    const timestamp = new Date().toISOString();

    let turtle = `
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix ex: <https://example.org/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

# Access Log Collection
ex:access-log a prov:Collection ;
    dct:title "Access Log for ${pod}'s Health Data" .

# Individual Access Record
ex:${accessId} a prov:Activity ;
    prov:startedAtTime "${timestamp}"^^xsd:dateTime ;
    prov:wasAssociatedWith <${evalRequest.requestingParty || 'anonymous'}> ;
    prov:used ${evalRequest.requestedTarget} ;
    ex:action ${evalRequest.requestedAction} ;
    ex:decision "${decision.permitted ? 'ALLOWED' : 'DENIED'}" .\n`;

    // Add purpose if available
    const purposeConstraint = evalRequest.context.find(c => c.leftOperand === 'odrl:purpose');
    if (purposeConstraint) {
      turtle += `ex:${accessId} ex:purpose ${purposeConstraint.rightOperand} .\n`;
    }

    // Add violation type if denied
    if (!decision.permitted && violationType) {
      turtle += `ex:${accessId} ex:violationType "${violationType}" .\n`;
    }

    // Add accessed fields
    accessedFields.forEach((field, idx) => {
      turtle += `ex:${accessId} ex:accessedField "${field}" .\n`;
    });

    // Generate compliance report (per the paper)
    if (!decision.permitted) {
      turtle += `
ex:${reportId} a report:PolicyReport ;
    dct:created "${timestamp}"^^xsd:dateTime ;
    report:policy ex:policy-blood-type ;
    report:ruleReport ex:violation-report-${reportId} .

ex:violation-report-${reportId} a report:RuleReport ;
    report:rule ex:permission-blood-type ;
    report:activationState report:Active ;
    report:performanceState report:NotPerformed ;
    report:deonticState report:Violated .\n`;
    } else {
      turtle += `
ex:${reportId} a report:PolicyReport ;
    dct:created "${timestamp}"^^xsd:dateTime ;
    report:policy ex:policy-blood-type ;
    report:ruleReport ex:permission-report-${reportId} .

ex:permission-report-${reportId} a report:RuleReport ;
    report:rule ex:permission-blood-type ;
    report:activationState report:Active ;
    report:performanceState report:Performed ;
    report:deonticState report:Fulfilled .\n`;
    }

    return turtle;
  }

  /**
   * Generate State of the World RDF (matching the provided example)
   * @param {Object} sotwData - State of the World data
   * @returns {string} Turtle representation
   */
  generateSotW(sotwData) {
    const sotwId = `sotw-${Date.now()}`;

    let turtle = `
@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dct: <http://purl.org/dc/terms/> .

# This file is continuously updated by monitoring system
:${sotwId} a :SotW ;
    dct:modified "${new Date().toISOString()}"^^xsd:dateTime ;
    :currentTime "${sotwData.currentTime}"^^xsd:dateTime .\n`;

    // Per-resource tracking
    if (sotwData.count && sotwData.count['schema:bloodType']) {
      const countData = sotwData.count['schema:bloodType'];
      turtle += `
:sotw-blood-type a :SotW ;
    :target ex:blood-type ;
    :count "${countData.count}"^^xsd:integer ;
    :lastAccessed "${countData.lastAccess}"^^xsd:dateTime ;
    :firstCollected "${countData.firstAccess}"^^xsd:dateTime .\n`;
    }

    return turtle;
  }

  /**
   * Generate violation report
   * @param {Object} params - Violation parameters
   * @returns {string} Turtle representation
   */
  generateViolationReport({
    pod,
    evalRequest,
    decision,
    violationType,
    constraint
  }) {
    const reportId = `violation-${Date.now()}`;
    const timestamp = new Date().toISOString();

    return `
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix ex: <https://example.org/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

# Violation Attempt
ex:${reportId} a prov:Activity ;
    prov:startedAtTime "${timestamp}"^^xsd:dateTime ;
    prov:wasAssociatedWith <${evalRequest.requestingParty || 'anonymous'}> ;
    prov:used ${evalRequest.requestedTarget} ;
    ex:action ${evalRequest.requestedAction} ;
    ex:decision "DENIED" ;
    ex:violationType "${violationType}" ;
    ex:constraintLeftOperand "${constraint.leftOperand}" ;
    ex:constraintOperator "${constraint.operator}" ;
    ex:constraintRightOperand "${constraint.rightOperand}" ;
    ex:actualValue "${constraint.actualValue}" .`;
  }
}