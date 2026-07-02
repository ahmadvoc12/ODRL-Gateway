/**
 * O-Prime enforcement helpers.
 *
 * Determines whether a policy decision should BLOCK a request in enforcement
 * mode. Only count and temporal violations block: their values come from
 * gateway-controlled sources (the usage counter and the server clock) and
 * express usage-aware conditions that Solid access control cannot. All other
 * constraints (purpose, legal basis, recipient, duty, and action prohibitions)
 * are recorded as accountability evidence; identity- and action-level allow/deny
 * is delegated to the Solid access-control layer.
 */

// O-Prime enforces only the usage-aware constraints that Solid's access-control
// layer (WAC/ACP) cannot express: count and temporal. Their values are resolved
// from gateway-controlled sources (the usage counter and the server clock).
// Action prohibitions and recipient (identity) allow/deny overlap Solid access
// control, so they are evaluated and RECORDED but not blocked here; their
// enforcement is delegated to the access-control layer.
const ENFORCED_OPERANDS = new Set(['odrl:count', 'odrl:dateTime']);

/**
 * True if a single violated-constraint record is one O-Prime enforces by
 * blocking (count or temporal). Decided by the grounding operand, not the
 * violationType, so a prohibition or identity check never blocks here.
 */
export function isTier1Violation(v) {
  if (!v) return false;
  if (v.violationType === 'ExcessiveAccessCount') return true;   // count
  const cs = Array.isArray(v.constraint) ? v.constraint : (v.constraint ? [v.constraint] : []);
  return cs.some(c => ENFORCED_OPERANDS.has(c?.leftOperand));    // temporal (or count)
}

/**
 * Given an engine decision, return the enforcement outcome.
 * @returns {{block: boolean, violations: Array}}
 */
export function enforcementOutcome(decision) {
  if (!decision || decision.permitted) return { block: false, violations: [] };
  const t1 = (decision.violatedConstraints || []).filter(isTier1Violation);
  return { block: t1.length > 0, violations: t1 };
}
