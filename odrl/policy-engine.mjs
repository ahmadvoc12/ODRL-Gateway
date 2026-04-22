/**
 * ODRL Policy Engine
 * Evaluasi ODRL policies terhadap Evaluation Request + State of the World
 * Sesuai paper: ODRL 2.2 standard
 */

export class ODRLPolicyEngine {
  
  /**
   * Constructor
   */
  constructor() {
    this.policies = new Map();
  }

  /**
   * Load ODRL policies dari object
   * @param {Object} policies - ODRL policies configuration
   */
  loadPolicies(policies) {
    this.policies = new Map(Object.entries(policies));
    console.log(`✅ ODRL Policy Engine loaded ${this.policies.size} policies`);
  }

  /**
   * Evaluate request terhadap policies
   * @param {Object} evalRequest - Evaluation Request
   * @param {Object} sotw - State of the World
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} Decision object
   */
  evaluate(evalRequest, sotw, accessedFields = []) {
    const decision = {
      permitted: true,
      reason: 'No constraints violated',
      matchedPolicies: [],
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    // Cek setiap policy
    for (const [policyId, policy] of this.policies.entries()) {
      const policyDecision = this.evaluatePolicy(policy, evalRequest, sotw, accessedFields);
      
      // Gabungkan hasil
      decision.matchedPolicies.push(...policyDecision.matchedPolicies);
      decision.violatedConstraints.push(...policyDecision.violatedConstraints);
      decision.evaluatedConstraints.push(...policyDecision.evaluatedConstraints);
      
      // Jika ada violation, set permitted = false
      if (!policyDecision.permitted) {
        decision.permitted = false;
        decision.reason = policyDecision.reason;
      }
    }

    return decision;
  }

  /**
   * Evaluate satu policy
   * @param {Object} policy - Policy object
   * @param {Object} evalRequest - Evaluation Request
   * @param {Object} sotw - State of the World
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} Policy decision
   */
  evaluatePolicy(policy, evalRequest, sotw, accessedFields) {
    const decision = {
      permitted: true,
      reason: 'Policy satisfied',
      matchedPolicies: [],
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    // Cek permission
    if (policy.permission) {
      const permissionDecision = this.evaluatePermission(
        policy.permission,
        evalRequest,
        sotw,
        accessedFields
      );
      
      if (!permissionDecision.permitted) {
        decision.permitted = false;
        decision.reason = permissionDecision.reason;
        decision.violatedConstraints.push(...permissionDecision.violatedConstraints);
      }
      
      decision.evaluatedConstraints.push(...permissionDecision.evaluatedConstraints);
    }

    // Cek prohibition
    if (policy.prohibition) {
      const prohibitionDecision = this.evaluateProhibition(
        policy.prohibition,
        evalRequest,
        sotw,
        accessedFields
      );
      
      if (!prohibitionDecision.permitted) {
        decision.permitted = false;
        decision.reason = prohibitionDecision.reason;
        decision.violatedConstraints.push(...prohibitionDecision.violatedConstraints);
      }
      
      decision.evaluatedConstraints.push(...prohibitionDecision.evaluatedConstraints);
    }

    if (decision.permitted) {
      decision.matchedPolicies.push(policy.uid);
    }

    return decision;
  }

  /**
   * Evaluate permission
   * @param {Object} permission - Permission object
   * @param {Object} evalRequest - Evaluation Request
   * @param {Object} sotw - State of the World
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} Decision
   */
  evaluatePermission(permission, evalRequest, sotw, accessedFields) {
    const decision = {
      permitted: true,
      reason: 'Permission granted',
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    // Cek action match
    if (permission.action && permission.action !== evalRequest.requestedAction) {
      return decision; // Skip jika action tidak match
    }

    // Cek constraint (jika ada)
    if (permission.constraint) {
      // Untuk count constraint, evaluasi per field
      if (permission.constraint.leftOperand === 'odrl:count' && accessedFields.length > 0) {
        for (const field of accessedFields) {
          const constraintDecision = this.evaluateConstraint(
            permission.constraint,
            evalRequest,
            sotw,
            field
          );
          
          decision.evaluatedConstraints.push({
            field: field,
            constraint: permission.constraint,
            result: constraintDecision
          });
          
          if (!constraintDecision.permitted) {
            decision.permitted = false;
            decision.reason = `ExcessiveAccessCount: ${constraintDecision.reason} for field "${field}"`;
            decision.violatedConstraints.push({
              field: field,
              constraint: permission.constraint,
              actualValue: constraintDecision.actualValue,
              violationType: 'ExcessiveAccessCount'
            });
          }
        }
      } else {
        // Evaluasi constraint biasa
        const constraintDecision = this.evaluateConstraint(
          permission.constraint,
          evalRequest,
          sotw
        );
        
        decision.evaluatedConstraints.push({
          constraint: permission.constraint,
          result: constraintDecision
        });
        
        if (!constraintDecision.permitted) {
          decision.permitted = false;
          decision.reason = constraintDecision.reason;
          decision.violatedConstraints.push({
            constraint: permission.constraint,
            actualValue: constraintDecision.actualValue,
            violationType: 'ConstraintViolation'
          });
        }
      }
    }

    return decision;
  }

  /**
   * Evaluate prohibition
   * @param {Object} prohibition - Prohibition object
   * @param {Object} evalRequest - Evaluation Request
   * @param {Object} sotw - State of the World
   * @param {Array} accessedFields - Fields yang diakses
   * @returns {Object} Decision
   */
  evaluateProhibition(prohibition, evalRequest, sotw, accessedFields) {
    const decision = {
      permitted: true,
      reason: 'No prohibition violated',
      violatedConstraints: [],
      evaluatedConstraints: []
    };

    // Jika prohibition match, maka access DITOLAK
    if (prohibition.action === evalRequest.requestedAction) {
      decision.permitted = false;
      decision.reason = `Action ${evalRequest.requestedAction} is prohibited`;
      decision.violatedConstraints.push({
        constraint: { leftOperand: 'action', operator: 'equals', rightOperand: prohibition.action },
        actualValue: evalRequest.requestedAction,
        violationType: 'ProhibitedAction'
      });
    }

    return decision;
  }

  /**
   * Evaluate constraint
   * Sesuai paper: (leftOperand, operator, rightOperand) triple
   * @param {Object} constraint - Constraint object
   * @param {Object} evalRequest - Evaluation Request
   * @param {Object} sotw - State of the World
   * @param {string} field - Field name (untuk count constraint)
   * @returns {Object} Constraint decision
   */
  evaluateConstraint(constraint, evalRequest, sotw, field = null) {
    const { leftOperand, operator, rightOperand } = constraint;
    
    // Mapping leftOperand ke sumber data
    let actualValue;
    
    switch (leftOperand) {
      case 'odrl:count':
        // Ambil count dari SotW untuk field tertentu
        actualValue = field ? (sotw.count[field]?.count || 0) : 0;
        break;
        
      case 'odrl:purpose':
        // Ambil purpose dari Evaluation Request context
        const purposeConstraint = evalRequest.context.find(c => c.leftOperand === 'odrl:purpose');
        actualValue = purposeConstraint?.rightOperand;
        break;
        
      case 'odrl:spatial':
        actualValue = sotw.currentLocation;
        break;
        
      case 'odrl:dateTime':
        actualValue = sotw.currentTime;
        break;
        
      default:
        console.warn(`⚠️ Unknown leftOperand: ${leftOperand}`);
        return { permitted: true, reason: 'unknown constraint', actualValue: null };
    }
    
    // Evaluasi operator
    let permitted = false;
    let reason = '';
    
    switch (operator) {
      case 'odrl:eq':
        permitted = actualValue === rightOperand;
        reason = permitted ? 'constraint matched' : `expected ${rightOperand}, got ${actualValue}`;
        break;
        
      case 'odrl:lteq': // less than or equal
        permitted = actualValue <= rightOperand;
        reason = permitted ? 'within limit' : `count ${actualValue} exceeds limit ${rightOperand}`;
        break;
        
      case 'odrl:lt': // less than
        permitted = actualValue < rightOperand;
        reason = permitted ? 'within limit' : `count ${actualValue} exceeds limit ${rightOperand}`;
        break;
        
      case 'odrl:gt': // greater than
        permitted = actualValue > rightOperand;
        reason = permitted ? 'above threshold' : `count ${actualValue} below threshold ${rightOperand}`;
        break;
        
      case 'odrl:gteq': // greater than or equal
        permitted = actualValue >= rightOperand;
        reason = permitted ? 'above threshold' : `count ${actualValue} below threshold ${rightOperand}`;
        break;
        
      default:
        console.warn(`⚠️ Unknown operator: ${operator}`);
        permitted = true;
        reason = 'unknown operator';
    }
    
    return { 
      permitted, 
      reason, 
      actualValue,
      leftOperand,
      operator,
      rightOperand
    };
  }

  /**
   * Get policy by ID
   * @param {string} policyId - Policy ID
   * @returns {Object|null} Policy object atau null
   */
  getPolicy(policyId) {
    return this.policies.get(policyId) || null;
  }

  /**
   * Get all policies
   * @returns {Map} All policies
   */
  getAllPolicies() {
    return this.policies;
  }
}