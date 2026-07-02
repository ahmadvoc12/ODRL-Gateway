/**
 * ODRL Evaluation Request Builder
 * Per the paper: formal description of the requested action
 * 
 * Competency Questions:
 * CQR1. What is the requested action?
 * CQR2. Who is the party issuing the evaluation request?
 * CQR3. What is the target asset of the evaluation request?
 * CQR4. When was the evaluation request issued?
 * CQR5. What additional contextual information can be included?
 */

export class EvaluationRequestBuilder {
  
  /**
   * Build an Evaluation Request from an HTTP request
   * @param {Object} req - HTTP request object
   * @param {string} pathname - Request pathname
   * @param {string} pod - Pod name
   * @returns {Object} Evaluation Request object
   */
  /**
   * Build Evaluation Request from HTTP request.
   * All security-relevant fields (purpose, legalBasis, recipient, issued) come
   * from verifiedContext - resolved by the gateway from server-controlled sources
   * (JWT, resource body, URL routing, server clock). X-* headers are NOT used
   * for constraint evaluation.
   *
   * @param {Object} verifiedContext - pre-resolved by resolveTrustedContext()
   */
  buildFromHttpRequest(req, pathname, pod, body, verifiedContext = {}) {
    const { method, headers } = req;
    const appName = verifiedContext.recipient || this.extractAppName(pathname);

    return {
      '@type': 'EvaluationRequest',
      requestedAction: this.mapHttpMethodToODRL(method),
      requestingParty: this.extractWebId(headers.authorization) || verifiedContext.clientId || null,
      requestedTarget: this.buildTargetIRI(pathname, pod),
      context: this.extractContext(headers, pathname),

      // Temporal: always server clock (verifiedContext.issued = new Date() in gateway)
      issued: verifiedContext.issued || new Date().toISOString(),

      pod,
      method,
      appName,

      // Constraint evaluation fields - from verified sources only
      purpose:    verifiedContext.purpose    || null,
      legalBasis: verifiedContext.legalBasis || null,
      recipient:  verifiedContext.recipient  || appName,
      location:   headers['x-location']     || null, // spatial - not a security constraint here

      // Trust provenance - logged in PROV-O, not used for evaluation logic
      trustSources: verifiedContext.trustSources || {},
      clientId:     verifiedContext.clientId     || null,
      issuer:       verifiedContext.issuer       || null,
    };
  }

  /**
   * Map HTTP method ke ODRL action
   * @param {string} method - HTTP method
   * @returns {string} ODRL action
   */
  mapHttpMethodToODRL(method) {
    const mapping = {
      'GET': 'odrl:read',
      'POST': 'odrl:create',
      'PUT': 'odrl:modify',
      'PATCH': 'odrl:modify',
      'DELETE': 'odrl:delete'
    };
    return mapping[method] || 'odrl:use';
  }

  /**
   * Extract the WebID from the Authorization header
   * @param {string} authHeader - Authorization header
   * @returns {string|null} WebID or null
   */
  extractWebId(authHeader) {
    if (!authHeader) return null;
    
    // Parse the WebID from the token (implementation depends on the auth mechanism)
    if (authHeader.includes('Bearer ')) {
      // In production, parse the JWT or Solid token to obtain the WebID
      return `https://user.solid.example/profile#${Date.now()}`;
    }
    
    return null;
  }

  /**
   * Build the target IRI from the pathname
   * @param {string} pathname - Request pathname
   * @param {string} pod - Pod name
   * @returns {string} Target IRI
   */
  buildTargetIRI(pathname, pod) {
    // Extract the resource identifier from the pathname
    if (pathname.includes('blood-type') || pathname.includes('bloodType')) {
      return 'ex:blood-type';
    }
    if (pathname.includes('health')) {
      return 'ex:health-records';
    }
    return `ex:resource-${pathname.replace(/[/]/g, '-')}`;
  }

  /**
   * Extract context from headers and pathname
   * @param {Object} headers - HTTP headers
   * @param {string} pathname - Request pathname
   * @returns {Array} Array of context constraints
   */
  extractContext(headers, pathname) {
    const context = [];

    // Purpose is resolved by the gateway via trusted sources (not from headers here)

    // 2. Extract app info
    const app = this.extractAppName(pathname);
    if (app) {
      context.push({
        leftOperand: 'ex:application',
        operator: 'odrl:eq',
        rightOperand: app
      });
    }

    // 3. Extract format preference from the Accept header
    const accept = headers['accept'];
    if (accept) {
      const formatConstraint = this.parseAcceptHeader(accept);
      if (formatConstraint) {
        context.push(formatConstraint);
      }
    }

    return context;
  }


  /**
   * Extract the app name from the pathname
   * @param {string} pathname - Request pathname
   * @returns {string} App name or "unknown-app"
   */
  extractAppName(pathname) {
    const seg = pathname.split("/").filter(Boolean);
    const idx = seg.indexOf("public");
    return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
  }

  /**
   * Parse Accept header ke constraint
   * @param {string} accept - Accept header value
   * @returns {Object|null} Constraint object or null
   */
  parseAcceptHeader(accept) {
    const formatMap = {
      'application/ld+json': 'application/ld+json',
      'text/turtle': 'text/turtle',
      'application/rdf+xml': 'application/rdf+xml'
    };

    for (const [mime, format] of Object.entries(formatMap)) {
      if (accept.includes(mime)) {
        return {
          leftOperand: 'odrl:fileFormat',
          operator: 'odrl:eq',
          rightOperand: format
        };
      }
    }

    return null;
  }

  /**
   * Convert the Evaluation Request to Turtle format (per the paper)
   * @param {Object} request - Evaluation Request object
   * @returns {string} Turtle representation
   */
  toTurtle(request) {
    const id = `req-${Date.now()}`;
    
    let turtle = `
@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

:${id} a :EvaluationRequest ;
    dct:issued "${request.issued}"^^xsd:dateTime ;
    :requestedAction ${request.requestedAction} ;
    :requestingParty <${request.requestingParty || 'anonymous'}> ;
    :requestedTarget ${request.requestedTarget} .\n`;

    request.context.forEach((ctx, idx) => {
      turtle += `
:${id}-ctx${idx} a odrl:Constraint ;
    odrl:leftOperand "${ctx.leftOperand}" ;
    odrl:operator "${ctx.operator}" ;
    odrl:rightOperand "${ctx.rightOperand}" .\n`;
    });

    return turtle;
  }
}