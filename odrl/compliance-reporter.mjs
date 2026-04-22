/**
 * Compliance Reporter
 * Generate compliance reports sesuai paper (report: namespace)
 * Untuk logging access attempts dan violations
 */

export class ComplianceReporter {
  
  /**
   * Generate compliance report untuk access attempt
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

    // Generate compliance report (sesuai paper)
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
   * Generate State of the World RDF (sesuai contoh Anda)
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