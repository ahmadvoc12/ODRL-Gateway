/**
 * O-Prime ODRL Policy Engine - Extended
 *
 * Evaluates ODRL 2.2 policies against an EvaluationRequest and SoTW.
 * Constraint types: count, purpose, legal-basis, temporal (range),
 *                   recipient, duty, prohibition.
 * Operators:        eq, lteq, lt, gt, gteq, isAnyOf
 * Deontic states:   Fulfilled | Violated | NonSet
 *                   (per ODRL Compliance Report Model)
 */

export class ODRLPolicyEngine {

  constructor() {
    this.policies = new Map();
    this.dutyLog = new Map(); // policyId -> {fulfilled, timestamp}
  }

  loadPolicies(policies) {
    this.policies = new Map(Object.entries(policies));
    console.log(`ODRL Policy Engine loaded ${this.policies.size} policies`);
  }

  getPolicy(policyId) {
    return this.policies.get(policyId) || null;
  }

  getAllPolicies() {
    return this.policies;
  }

  // Public entry point

  /**
   * @param {Object} evalRequest  - EvaluationRequest (from request-builder)
   * @param {Object} sotw         - State of the World
   * @param {string[]} accessedFields - Sensitive field IRIs accessed
   * @param {string} requestedAction  - ex:read | ex:create | ex:update | ex:delete
   * @returns {Object} decision
   */
  evaluate(evalRequest, sotw, accessedFields = [], requestedAction = 'ex:read') {
    const decision = {
      permitted: true,
      reason: 'No constraints violated',
      deonticState: 'NonSet',
      matchedPolicies: [],
      violatedConstraints: [],
      evaluatedConstraints: [],
      dutyObligations: []
    };

    for (const [policyId, policy] of this.policies.entries()) {
      const pd = this._evaluatePolicy(policy, evalRequest, sotw, accessedFields, requestedAction);

      decision.matchedPolicies.push(...pd.matchedPolicies);
      decision.violatedConstraints.push(...pd.violatedConstraints);
      decision.evaluatedConstraints.push(...pd.evaluatedConstraints);
      decision.dutyObligations.push(...(pd.dutyObligations || []));

      if (!pd.permitted) {
        decision.permitted = false;
        decision.reason = pd.reason;
      }
    }

    // Deontic state: only NonSet when truly no policy applied AND no violations
    if (decision.violatedConstraints.length > 0) {
      decision.deonticState = 'Violated';
    } else if (decision.matchedPolicies.length > 0) {
      decision.deonticState = 'Fulfilled';
    }
    // else remains NonSet

    return decision;
  }

  // Policy-level evaluation

  _evaluatePolicy(policy, evalRequest, sotw, accessedFields, requestedAction) {
    const decision = {
      permitted: true,
      reason: 'Policy satisfied',
      matchedPolicies: [],
      violatedConstraints: [],
      evaluatedConstraints: [],
      dutyObligations: []
    };

    // --- Permission ---------------------------------------------------------
    if (policy.permission) {
      const perms = Array.isArray(policy.permission)
        ? policy.permission : [policy.permission];

      for (const perm of perms) {
        if (!this._actionMatches(perm.actions || perm.action, requestedAction)) continue;

        const pd = this._evaluatePermission(perm, evalRequest, sotw, accessedFields, requestedAction);
        decision.evaluatedConstraints.push(...pd.evaluatedConstraints);

        if (!pd.permitted) {
          decision.permitted = false;
          decision.reason = pd.reason;
          decision.violatedConstraints.push(...pd.violatedConstraints);
        } else {
          decision.matchedPolicies.push(policy.uid || policy.resource || policy.title);
        }

        // Duty obligations attached to permission
        if (perm.duty) {
          decision.dutyObligations.push(...this._collectDuties(perm.duty, policy));
        }
      }
    }

    // --- Prohibition --------------------------------------------------------
    if (policy.prohibition) {
      const prohibitions = Array.isArray(policy.prohibition)
        ? policy.prohibition : [policy.prohibition];

      for (const prohib of prohibitions) {
        if (!this._actionMatches(prohib.actions || prohib.action, requestedAction)) continue;

        const pd = this._evaluateProhibition(prohib, evalRequest, sotw, accessedFields);
        decision.evaluatedConstraints.push(...pd.evaluatedConstraints);

        if (!pd.permitted) {
          decision.permitted = false;
          decision.reason = pd.reason;
          decision.violatedConstraints.push(...pd.violatedConstraints);
        }
      }
    }

    // --- Top-level duty (obligation regardless of permission result) ---------
    if (policy.duty) {
      decision.dutyObligations.push(...this._collectDuties(policy.duty, policy));
    }

    return decision;
  }

  // Permission evaluation

  _evaluatePermission(permission, evalRequest, sotw, accessedFields, requestedAction) {
    const decision = {
      permitted: true,
      reason: 'Permission granted',
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    if (!permission.constraint) return decision;

    // Support both single constraint and AND-compound (array)
    const constraints = Array.isArray(permission.constraint)
      ? permission.constraint : [permission.constraint];

    for (const constraint of constraints) {
      if (constraint.leftOperand === 'odrl:count') {
        // Count is per accessed-field
        for (const field of accessedFields) {
          const cd = this._evaluateConstraint(constraint, evalRequest, sotw, field, requestedAction);
          decision.evaluatedConstraints.push({ field, constraint, result: cd });

          if (!cd.permitted) {
            decision.permitted = false;
            decision.reason = `ExcessiveAccessCount: ${cd.reason} for field "${field}"`;
            decision.violatedConstraints.push({
              field, constraint,
              actualValue: cd.actualValue,
              violationType: 'ExcessiveAccessCount'
            });
          }
        }
      } else {
        const cd = this._evaluateConstraint(constraint, evalRequest, sotw, null, requestedAction);
        decision.evaluatedConstraints.push({ constraint, result: cd });

        if (!cd.permitted) {
          decision.permitted = false;
          decision.reason = cd.reason;
          const lo = constraint.leftOperand;
          const trustKey = lo === 'odrl:purpose' ? 'purpose'
            : (lo === 'dpv:hasLegalBasis' || lo === 'odrl:legalBasis') ? 'legalBasis'
            : lo === 'odrl:dateTime' ? 'temporal'
            : (lo === 'odrl:recipient' || lo === 'ex:recipient') ? 'recipient'
            : null;
          decision.violatedConstraints.push({
            constraint,
            actualValue: cd.actualValue,
            violationType: 'ConstraintViolation',
            trustSource: trustKey ? (evalRequest.trustSources?.[trustKey] || 'unknown') : 'n/a',
          });
        }
      }
    }

    return decision;
  }

  // Prohibition evaluation

  _evaluateProhibition(prohibition, evalRequest, sotw, accessedFields) {
    const decision = {
      permitted: true,
      reason: 'No prohibition triggered',
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    // Prohibition with no constraint = unconditional
    if (!prohibition.constraint) {
      decision.permitted = false;
      decision.reason = `Action prohibited unconditionally`;
      decision.violatedConstraints.push({
        constraint: { leftOperand: 'action', operator: 'eq', rightOperand: prohibition.action },
        actualValue: evalRequest.requestedAction,
        violationType: 'ProhibitedAction'
      });
      return decision;
    }

    // Prohibition with constraint = conditional - triggered if all constraints hold
    const constraints = Array.isArray(prohibition.constraint)
      ? prohibition.constraint : [prohibition.constraint];

    const allHold = constraints.every(c => {
      const cd = this._evaluateConstraint(c, evalRequest, sotw, null, null);
      decision.evaluatedConstraints.push({ constraint: c, result: cd });
      return cd.permitted;
    });

    if (allHold) {
      decision.permitted = false;
      decision.reason = `Prohibition triggered: ${prohibition.reason || 'prohibited action'}`;
      decision.violatedConstraints.push({
        constraint: prohibition.constraint,
        violationType: 'ProhibitionTriggered'
      });
    }

    return decision;
  }

  // Constraint evaluation

  _evaluateConstraint(constraint, evalRequest, sotw, field = null, requestedAction = null) {
    const { leftOperand, operator, rightOperand } = constraint;
    let actualValue;

    switch (leftOperand) {

      // Count (per-field, per-action-type)
      case 'odrl:count': {
        const fieldKey = field ? this._normalizeIRI(field) : null;
        const action = requestedAction || 'ex:read';
        actualValue = sotw.count?.[fieldKey]?.count
          ?? sotw.count?.[field]?.count
          ?? 0;
        break;
      }

      // Purpose - trust: jwt-trusted-issuer > app-registry > url-inferred (never client header)
      case 'odrl:purpose': {
        actualValue = evalRequest.purpose || 'dpv:UnknownPurpose';
        break;
      }

      // Legal basis - trust: resource-data (data subject declaration) > jwt-trusted-issuer
      case 'dpv:hasLegalBasis':
      case 'odrl:legalBasis': {
        actualValue = evalRequest.legalBasis || null;
        break;
      }

      // Temporal - trust: server-clock only (gateway sets issued = new Date())
      case 'odrl:dateTime': {
        actualValue = evalRequest.issued || new Date().toISOString();
        break;
      }

      // Recipient - trust: jwt-verified (client_id from Solid-OIDC) > url-inferred
      case 'odrl:recipient':
      case 'ex:recipient': {
        actualValue = evalRequest.recipient || evalRequest.appName || 'unknown-app';
        break;
      }

      // Spatial location
      case 'odrl:spatial': {
        actualValue = sotw.currentLocation || evalRequest.location || null;
        break;
      }

      default:
        console.warn(`Unknown leftOperand: ${leftOperand}`);
        return { permitted: true, reason: 'unknown constraint skipped', actualValue: null };
    }

    return this._applyOperator(operator, actualValue, rightOperand, leftOperand);
  }

  // Operator application

  _applyOperator(operator, actual, expected, leftOperand) {
    let permitted = false;
    let reason = '';

    switch (operator) {
      case 'odrl:eq':
        permitted = String(actual) === String(expected);
        reason = permitted ? 'constraint satisfied'
          : `expected "${expected}", got "${actual}"`;
        break;

      case 'odrl:neq':
        permitted = String(actual) !== String(expected);
        reason = permitted ? 'constraint satisfied'
          : `"${actual}" is not allowed`;
        break;

      case 'odrl:lteq': {
        const cmp = this._compareNumOrDate(actual, expected);
        permitted = cmp <= 0;
        reason = permitted ? 'within limit'
          : `${actual} exceeds limit ${expected}`;
        break;
      }

      case 'odrl:lt': {
        const cmp = this._compareNumOrDate(actual, expected);
        permitted = cmp < 0;
        reason = permitted ? 'within limit'
          : `${actual} not below ${expected}`;
        break;
      }

      case 'odrl:gteq': {
        const cmp = this._compareNumOrDate(actual, expected);
        permitted = cmp >= 0;
        reason = permitted ? 'at or after start'
          : `"${actual}" is before required start "${expected}"`;
        break;
      }

      case 'odrl:gt': {
        const cmp = this._compareNumOrDate(actual, expected);
        permitted = cmp > 0;
        reason = permitted ? 'above threshold'
          : `"${actual}" is not after "${expected}"`;
        break;
      }

      case 'odrl:isAnyOf': {
        const allowed = Array.isArray(expected) ? expected : [expected];
        permitted = allowed.some(v => String(v) === String(actual));
        reason = permitted ? 'recipient is allowed'
          : `"${actual}" not in allowed set [${allowed.join(', ')}]`;
        break;
      }

      default:
        console.warn(`Unknown operator: ${operator}`);
        permitted = true;
        reason = 'unknown operator, defaulting to permitted';
    }

    return { permitted, reason, actualValue: actual, operator, rightOperand: expected };
  }

  // Duty collection

  _collectDuties(dutySpec, policy) {
    const duties = Array.isArray(dutySpec) ? dutySpec : [dutySpec];
    return duties.map(d => ({
      action: d.action,
      target: d.target || policy.resource,
      fulfilled: this.dutyLog.get(`${policy.uid}:${d.action}`)?.fulfilled || false,
      policyId: policy.uid || policy.resource
    }));
  }

  recordDutyFulfilled(policyId, action) {
    this.dutyLog.set(`${policyId}:${action}`, { fulfilled: true, timestamp: new Date().toISOString() });
  }

  // Helpers

  _actionMatches(policyAction, requestedAction) {
    if (!policyAction) return true;
    const actions = Array.isArray(policyAction) ? policyAction : [policyAction];
    const ACTION_HIERARCHY = {
      'ex:read': ['odrl:use', 'odrl:read'],
      'ex:create': ['odrl:use', 'odrl:write'],
      'ex:update': ['odrl:use', 'odrl:modify'],
      'ex:delete': ['odrl:transfer', 'odrl:delete'],
      'odrl:read': ['odrl:use'],
      'odrl:write': ['odrl:use'],
      'odrl:modify': ['odrl:use'],
      'odrl:distribute': [],
      'odrl:use': [],
    };

    const req = requestedAction || 'ex:read';
    const parents = [req, ...(ACTION_HIERARCHY[req] || [])];
    return actions.some(a => parents.includes(a) || a === 'odrl:use');
  }

  _contextValue(evalRequest, leftOperand) {
    if (!Array.isArray(evalRequest.context)) return null;
    const entry = evalRequest.context.find(c => c.leftOperand === leftOperand);
    return entry?.rightOperand || null;
  }

  _normalizeIRI(iri) {
    return iri.replace(/^<|>$/g, '');
  }

  _compareDateTime(a, b) {
    const da = new Date(a), db = new Date(b);
    if (isNaN(da) || isNaN(db)) return 0;
    return da - db;
  }

  _compareNumOrDate(a, b) {
    const na = Number(a), nb = Number(b);
    if (!isNaN(na) && !isNaN(nb)) return na - nb;
    return this._compareDateTime(a, b);
  }
}
