/**
 * ODRL Evaluation Request Builder
 * Sesuai paper: Formal description of requested action
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
   * Build Evaluation Request dari HTTP request
   * @param {Object} req - HTTP request object
   * @param {string} pathname - Request pathname
   * @param {string} pod - Pod name
   * @returns {Object} Evaluation Request object
   */
  buildFromHttpRequest(req, pathname, pod) {
    const { method, headers } = req;
    
    return {
      '@type': 'EvaluationRequest',
      requestedAction: this.mapHttpMethodToODRL(method),
      requestingParty: this.extractWebId(headers.authorization),
      requestedTarget: this.buildTargetIRI(pathname, pod),
      context: this.extractContext(headers, pathname),
      issued: new Date().toISOString(),
      pod: pod,
      method: method,
      appName: this.extractAppName(pathname)
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
   * Extract WebID dari Authorization header
   * @param {string} authHeader - Authorization header
   * @returns {string|null} WebID atau null
   */
  extractWebId(authHeader) {
    if (!authHeader) return null;
    
    // Parse WebID dari token (implementasi tergantung auth mechanism)
    if (authHeader.includes('Bearer ')) {
      // Dalam production, parse JWT atau Solid token untuk dapatkan WebID
      return `https://user.solid.example/profile#${Date.now()}`;
    }
    
    return null;
  }

  /**
   * Build target IRI dari pathname
   * @param {string} pathname - Request pathname
   * @param {string} pod - Pod name
   * @returns {string} Target IRI
   */
  buildTargetIRI(pathname, pod) {
    // Extract resource identifier dari pathname
    if (pathname.includes('blood-type') || pathname.includes('bloodType')) {
      return 'ex:blood-type';
    }
    if (pathname.includes('health')) {
      return 'ex:health-records';
    }
    return `ex:resource-${pathname.replace(/[/]/g, '-')}`;
  }

  /**
   * Extract context dari headers dan pathname
   * @param {Object} headers - HTTP headers
   * @param {string} pathname - Request pathname
   * @returns {Array} Array of context constraints
   */
  extractContext(headers, pathname) {
    const context = [];

    // 1. Extract purpose dari header X-Purpose atau query params
    const purpose = headers['x-purpose'] || this.inferPurpose(pathname);
    if (purpose) {
      context.push({
        leftOperand: 'odrl:purpose',
        operator: 'odrl:eq',
        rightOperand: purpose
      });
    }

    // 2. Extract app info
    const app = this.extractAppName(pathname);
    if (app) {
      context.push({
        leftOperand: 'ex:application',
        operator: 'odrl:eq',
        rightOperand: app
      });
    }

    // 3. Extract format preference dari Accept header
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
   * Infer purpose dari pathname
   * @param {string} pathname - Request pathname
   * @returns {string} Purpose dalam format DPV
   */
  inferPurpose(pathname) {
    pathname = pathname.toLowerCase();
    
    if (pathname.includes('health') || pathname.includes('medical') || pathname.includes('clinic')) {
      return 'dpv:HealthcarePurpose';
    }
    if (pathname.includes('research') || pathname.includes('study')) {
      return 'dpv:ResearchPurpose';
    }
    if (pathname.includes('analytics') || pathname.includes('stats')) {
      return 'dpv:AnalyticsPurpose';
    }
    if (pathname.includes('marketing') || pathname.includes('promo')) {
      return 'dpv:MarketingPurpose';
    }
    
    return 'dpv:UnknownPurpose';
  }

  /**
   * Extract app name dari pathname
   * @param {string} pathname - Request pathname
   * @returns {string} App name atau "unknown-app"
   */
  extractAppName(pathname) {
    const seg = pathname.split("/").filter(Boolean);
    const idx = seg.indexOf("public");
    return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
  }

  /**
   * Parse Accept header ke constraint
   * @param {string} accept - Accept header value
   * @returns {Object|null} Constraint object atau null
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
   * Convert Evaluation Request ke Turtle format (sesuai paper)
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