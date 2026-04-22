/**
 * State of the World Provider
 * Sesuai paper: Real-world information for policy evaluation
 * 
 * Competency Questions:
 * CQS1. What is the current time?
 * CQS2. What is the location of a party?
 * CQS3. What assets are part of the asset collection?
 * CQS4. Which parties are part of the party collection?
 * CQS5. What actions were already performed or attempted?
 * CQS6. How many times has a rule been exercised?
 * CQS7. What information is available about an event?
 * CQS8. How long has a rule been exercised?
 * CQS9. Which recipients can receive the result?
 * CQS10. Has a financial payment been made?
 */

import { getAccessCounter } from './access-counter.mjs';

export class StateOfTheWorldProvider {
  constructor(dataRoot) {
    this.dataRoot = dataRoot;
    this.accessCounter = getAccessCounter(dataRoot);
    this.locationCache = new Map();
  }

  /**
   * Build State of the World untuk evaluasi
   * @param {string} pod - Pod name
   * @param {Object} evalRequest - Evaluation Request
   * @param {string} pathname - Request pathname
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} State of the World object
   */
  async build(pod, evalRequest, pathname, accessedFields = []) {
    const app = this.extractAppName(pathname);
    
    return {
      '@type': 'SotW',
      currentTime: new Date().toISOString(),
      currentLocation: await this.getLocation(evalRequest.requestingParty),
      partyCollection: await this.getPartyCollections(evalRequest.requestingParty),
      assetCollection: await this.getAssetCollections(pathname),
      existingReport: await this.getExistingReports(pod),
      count: this.buildCountState(pod, app, accessedFields),
      paidAmount: null,
      recipient: null,
      event: null
    };
  }

  /**
   * Get current location (bisa dari IP geolocation atau cache)
   * @param {string} webId - WebID of requesting party
   * @returns {string} Location URI (ISO 3166)
   */
  async getLocation(webId) {
    // Implementation: bisa dari IP geolocation atau profile
    // Untuk demo, return hardcoded location (Indonesia)
    return 'https://www.iso.org/obp/ui/#iso:code:3166:ID';
  }

  /**
   * Get party collections (group memberships)
   * @param {string} webId - WebID of requesting party
   * @returns {Array} Array of party collection URIs
   */
  async getPartyCollections(webId) {
    // Implementation: fetch dari Solid profile atau external directory
    // Untuk demo, return hardcoded
    if (!webId) return [];
    
    return ['ex:HealthcareStaff'];
  }

  /**
   * Get asset collections untuk pathname
   * @param {string} pathname - Request pathname
   * @returns {Array} Array of asset collection URIs
   */
  async getAssetCollections(pathname) {
    // Implementation: bisa scan pod structure atau dari metadata
    if (pathname.includes('health') || pathname.includes('medical')) {
      return ['ex:health-records'];
    }
    
    return [];
  }

  /**
   * Get existing reports (previous audit logs, fulfilled duties)
   * @param {string} pod - Pod name
   * @returns {Array} Array of report URIs
   */
  async getExistingReports(pod) {
    // Implementation: parse audit logs untuk extract fulfilled duties
    // Untuk demo, return empty
    return [];
  }

  /**
   * Build count state untuk fields yang diakses
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} Count state object
   */
  buildCountState(pod, app, accessedFields) {
    const countState = {};
    
    accessedFields.forEach(field => {
      const data = this.accessCounter.get(pod, app, field);
      if (data) {
        countState[field] = {
          count: data.count,
          lastAccess: data.lastAccess,
          firstAccess: data.firstAccess
        };
      } else {
        countState[field] = {
          count: 0,
          lastAccess: null,
          firstAccess: null
        };
      }
    });
    
    return countState;
  }

  /**
   * Extract app name dari pathname
   * @param {string} pathname - Request pathname
   * @returns {string} App name
   */
  extractAppName(pathname) {
    const seg = pathname.split("/").filter(Boolean);
    const idx = seg.indexOf("public");
    return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
  }

  /**
   * Increment access count untuk field
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name
   * @returns {Object} New count data
   */
  async incrementAccessCount(pod, app, field) {
    return await this.accessCounter.increment(pod, app, field);
  }

  /**
   * Convert State of the World ke Turtle format (sesuai paper)
   * @param {Object} sotw - State of the World object
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name
   * @returns {string} Turtle representation
   */
  toTurtle(sotw, pod, app, field) {
    const sotwId = `sotw-${Date.now()}`;
    const fieldId = field.replace(/[:/]/g, '-');
    
    let turtle = `
@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dct: <http://purl.org/dc/terms/> .

:${sotwId} a :SotW ;
    dct:modified "${new Date().toISOString()}"^^xsd:dateTime ;
    :currentTime "${sotw.currentTime}"^^xsd:dateTime .\n`;

    // Party collections
    sotw.partyCollection.forEach((collection, idx) => {
      turtle += `:${sotwId} :partyCollection ${collection} .\n`;
    });

    // Asset collections
    sotw.assetCollection.forEach((collection, idx) => {
      turtle += `:${sotwId} :assetCollection ${collection} .\n`;
    });

    // Count state untuk field tertentu
    if (field && sotw.count[field]) {
      const countData = sotw.count[field];
      turtle += `
:${sotwId}-${fieldId} a :SotW ;
    :target ex:blood-type ;
    :count "${countData.count}"^^xsd:integer ;
    :lastAccessed "${countData.lastAccess}"^^xsd:dateTime ;
    :firstCollected "${countData.firstAccess}"^^xsd:dateTime .\n`;
    }

    // Existing reports
    if (sotw.existingReport && sotw.existingReport.length > 0) {
      sotw.existingReport.forEach((report, idx) => {
        turtle += `:${sotwId} :existingReport ${report} .\n`;
      });
    }

    return turtle;
  }

  /**
   * Generate SotW RDF untuk monitoring (sesuai contoh Anda)
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name
   * @returns {string} Turtle representation
   */
  async generateMonitoringSotW(pod, app, field) {
    const countData = this.accessCounter.get(pod, app, field);
    if (!countData) return null;

    const sotwId = `sotw-current`;
    const fieldId = `sotw-blood-type`;
    
    return `
@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dct: <http://purl.org/dc/terms/> .

:${sotwId} a :SotW ;
    dct:modified "${new Date().toISOString()}"^^xsd:dateTime ;
    :currentTime "${new Date().toISOString()}"^^xsd:dateTime .

:${fieldId} a :SotW ;
    :target ex:blood-type ;
    :count "${countData.count}"^^xsd:integer ;
    :lastAccessed "${countData.lastAccess}"^^xsd:dateTime ;
    :firstCollected "${countData.firstAccess}"^^xsd:dateTime .`;
  }
}