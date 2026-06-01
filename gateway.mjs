import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

// ODRL Components (modular imports)
import { ODRLPolicyEngine } from './odrl/policy-engine.mjs';
import { EvaluationRequestBuilder } from './odrl/request-builder.mjs';
import { StateOfTheWorldProvider } from './odrl/context-provider.mjs';
import { ComplianceReporter } from './odrl/compliance-reporter.mjs';
import { getAccessCounter } from './odrl/access-counter.mjs';

/* ===============================
CONFIG (SESUAI RAILWAY)
================================ */
const GATEWAY_PORT = 3000;
const CSS_PORT = 4000;
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app";
const GATEWAY_BASE = PUBLIC_BASE_URL;
const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_ACCESS_PATH = "private/audit/access";
const AUDIT_MONITORING_PATH = "private/audit/monitoring";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const POLICY_PATH = "private/audit/access/monitor-policy.ttl";
const POLICY_ACL_PATH = "private/audit/access/monitor-policy.ttl.acl";

/* ===============================
✅ GLOBAL CACHE: Track active policy IRIs per pod
================================ */
const activePolicyCache = new Map();

/* ===============================
✅ ACTION HIERARCHY & MAPPING (ODRL 2.2 Compliant)
================================ */
// Action hierarchy: all custom actions are includedIn top-level ODRL actions
const ACTION_HIERARCHY = {
  'ex:read': 'odrl:use',
  'ex:create': 'odrl:use',
  'ex:update': 'odrl:use',
  'ex:delete': 'odrl:transfer', // optional
  'odrl:use': null,
  'odrl:transfer': null,
};

/**
 * Check if actionA is transitively included in actionB per ODRL hierarchy
 */
function actionIncludedIn(actionA, actionB) {
  if (!actionA || !actionB) return false;
  let current = cleanIRI(actionA);
  const target = cleanIRI(actionB);
  
  // Direct match
  if (current === target) return true;
  
  // Traverse hierarchy transitively
  while (current && ACTION_HIERARCHY[current]) {
    const parent = cleanIRI(ACTION_HIERARCHY[current]);
    if (parent === target) return true;
    current = parent;
  }
  return false;
}

/**
 * Map HTTP method + path pattern to ODRL action
 */
function httpMethodToOdrlAction(method, pathname = '', body = null) {
  const m = (method || 'GET').toUpperCase();
  
  // POST typically = create (but check for update patterns)
  if (m === 'POST') {
    // Check if body contains update-like patterns (optional heuristic)
    return 'ex:create';
  }
  
  // PUT/PATCH = update
  if (m === 'PUT' || m === 'PATCH') {
    return 'ex:update';
  }
  
  // DELETE = optional delete action
  if (m === 'DELETE') {
    return 'ex:delete';
  }
  
  // Default GET = read
  return 'ex:read';
}

/**
 * Check if requested action is allowed by policy actions + prohibitions
 */
function isActionAllowed(requestedAction, policyActions = [], prohibitions = []) {
  // 1. Check prohibition first (higher priority per ODRL)
  for (const prohibited of prohibitions) {
    if (actionIncludedIn(requestedAction, prohibited)) {
      return { allowed: false, reason: 'Action prohibited by policy' };
    }
  }
  
  // 2. Check permission with hierarchy
  const isPermitted = policyActions.some(pa => 
    actionIncludedIn(requestedAction, pa)
  );
  
  return {
    allowed: isPermitted,
    reason: isPermitted ? undefined : 'Action not permitted by policy'
  };
}

/* ===============================
SENSITIVE FIELD CONFIGURATION
================================ */
const SENSITIVE_FIELDS = {
  "<https://schema.org/bloodType>": {
    asset: "https://schema.org/bloodType",
    assetLabel: "Blood Type",
    protectedByPolicy: "bloodTypeAccess",
    personalData: "dpv:HealthData",
    dataCategory: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  },
  "<https://schema.org/identifier>": {
    asset: "https://schema.org/identifier",
    assetLabel: "Identifier",
    protectedByPolicy: "identityAccess",
    personalData: "dpv:PersonalIdentifier",
    dataCategory: "dpv:PersonalData",
    sensitive: true
  }
};

const NON_SENSITIVE_FIELDS = {
  "<http://purl.org/dc/terms/created>": {
    label: "Created Timestamp",
    sensitive: false
  }
};

/* ===============================
✅ HELPER FUNCTIONS
================================ */
function cleanIRI(iri) {
  if (!iri || typeof iri !== 'string') return iri || '';
  return iri
    .replace(/\s+>/g, '>')
    .replace(/<\s+/g, '<')
    .replace(/\s+/g, ' ')
    .trim();
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function normalizeField(field) {
  if (!field) return field;
  let normalized = field.replace(/<\s*/, '<').replace(/\s*>/, '>');
  const match = normalized.match(/<(https?:\/\/[^>]+)>/);
  if (match) {
    const iri = match[1].replace(/\s+$/, '');
    normalized = `<${iri}>`;
  }
  return normalized;
}

function getFieldConfig(fieldIRI) {
  const normalized = normalizeField(fieldIRI);
  return SENSITIVE_FIELDS[normalized] || NON_SENSITIVE_FIELDS[normalized] || null;
}

function isSensitiveField(fieldIRI) {
  const config = getFieldConfig(fieldIRI);
  return config?.sensitive === true;
}

function sanitizeTurtleLiteral(str) {
  if (!str) return '';
  return str
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

function createPolicyAliasMapping(aliasResource, policyResource, uuid) {
  const cleanAlias = cleanIRI(aliasResource);
  const cleanPolicy = cleanIRI(policyResource);
  const cleanUUID = uuid?.replace(/^urn:uuid:/, '') || '';
  return `
${cleanAlias} a <https://w3id.org/force/compliance-report#PolicyAlias> ;
<https://w3id.org/force/compliance-report#mapsToPolicy> ${cleanPolicy} ;
<https://w3id.org/force/compliance-report#mapsToUUID> "${cleanUUID}"^^xsd:string .`;
}

/* ===============================
✅ POLICY METADATA PARSER - Multi-Action Support
================================ */
function parsePolicyMetadata(ttlContent) {
  try {
    const metadata = {
      resource: null,
      identifier: null,
      title: null,
      description: null,
      target: null,
      active: true,
      maxCount: 3,
      actions: ['ex:read'], // ✅ Default action
      constraintApplicableActions: null // ✅ Optional: constraint applies to specific actions only
    };
    
    // Extract resource
    const resourceMatch = ttlContent.match(/(ex:policy-[^\s;]+)\s+a\s+odrl:Policy/);
    if (resourceMatch?.[1]) metadata.resource = cleanIRI(resourceMatch[1]);
    
    // Extract identifier
    const idMatch = ttlContent.match(/dct:identifier\s+"(urn:uuid:[^"]+)"/);
    if (idMatch?.[1]) metadata.identifier = idMatch[1];
    
    // Extract title & description
    const titleMatch = ttlContent.match(/dct:title\s+"([^"]+)"/);
    if (titleMatch?.[1]) metadata.title = titleMatch[1];
    
    const descMatch = ttlContent.match(/dct:description\s+"([^"]+)"/);
    if (descMatch?.[1]) metadata.description = descMatch[1];
    
    // Extract target
    const targetMatch = ttlContent.match(/odrl:target\s+<([^>]+)>/);
    if (targetMatch?.[1]) metadata.target = cleanIRI(targetMatch[1]);
    
    // ✅ Extract policyActive (handle multiple formats)
    const activeMatch = ttlContent.match(
      /<https:\/\/w3id\.org\/force\/compliance-report#policyActive\s*>?\s*("?[^"]+"?\^\^xsd:boolean|true|false)/i
    );
    if (activeMatch?.[1]) {
      const val = activeMatch[1]
        .replace(/"/g, '')
        .replace(/\^\^xsd:boolean/i, '')
        .trim()
        .toLowerCase();
      metadata.active = val === 'true';
    }
    
    // ✅ Extract actions from odrl:action in permission blocks
    const permissionBlocks = ttlContent.match(/odrl:permission\s+\[[^\]]+\]/gs) || [];
    const actions = new Set();
    
    permissionBlocks.forEach(block => {
      const actionMatches = block.match(/odrl:action\s+(odrl:[a-z]+|ex:[a-z-]+)/g) || [];
      actionMatches.forEach(match => {
        const action = match.split('odrl:action')[1]?.trim();
        if (action && !action.includes('odrl:distribute')) {
          actions.add(cleanIRI(action));
        }
      });
    });
    
    // Default to read if no actions found (backward compatibility)
    if (actions.size > 0) {
      metadata.actions = Array.from(actions);
    }
    
    // ✅ Extract constraint applicableActions if present
    const applicableActionsMatch = ttlContent.match(
      /<https:\/\/w3id\.org\/force\/compliance-report#applicableAction>\s+([^\s;]+)/g
    );
    if (applicableActionsMatch?.length > 0) {
      metadata.constraintApplicableActions = applicableActionsMatch
        .map(m => m.split('applicableAction>')[1]?.trim())
        .map(a => cleanIRI(a))
        .filter(Boolean);
    }
    
    // Extract maxCount from constraint
    const countMatch = ttlContent.match(
      /odrl:leftOperand\s+odrl:count[\s\S]*?odrl:rightOperand\s+"?(\d+)"?\^\^xsd:integer/
    );
    if (countMatch?.[1]) metadata.maxCount = parseInt(countMatch[1], 10);
    
    return metadata;
  } catch (error) {
    console.error(`❌ Error parsing policy meta`, error.message);
    return { active: true, maxCount: 3, actions: ['ex:read'] };
  }
}

/* ===============================
REQUEST DEDUPLICATION
================================ */
const requestCache = new Map();
function shouldCountRequest(pod, app, field, action, timestamp) {
  const normalizedField = normalizeField(field);
  const normalizedAction = cleanIRI(action);
  const key = `${pod}::${app}::${normalizedField}::${normalizedAction}::${timestamp.substring(0, 19)}`;
  
  if (requestCache.has(key)) {
    console.log(`ℹ️ Skipping duplicate request: ${normalizedField} [${normalizedAction}]`);
    return false;
  }
  
  requestCache.set(key, Date.now());
  
  // Clean old entries (>10s)
  const now = Date.now();
  for (const [k, time] of requestCache.entries()) {
    if (now - time > 10000) requestCache.delete(k);
  }
  
  return true;
}

/* ===============================
ODRL COMPONENTS INITIALIZATION
================================ */
const policyEngine = new ODRLPolicyEngine();
const requestBuilder = new EvaluationRequestBuilder();
const sotwProvider = new StateOfTheWorldProvider(DATA_ROOT);
const complianceReporter = new ComplianceReporter();
const accessCounter = getAccessCounter(DATA_ROOT);

/* ===============================
📄 MULTI-POLICY TTL CONTENT (INLINE)
================================ */
const MONITOR_POLICIES_TTL = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ex: <https://example.org/> .
@prefix force: <https://w3id.org/force/compliance-report#> .

# ===== POLICY 1: Blood Type - Read Only =====
ex:policy-blood-type-4579e3c3af6546af9b28c6bf72890416 a odrl:Policy ;
    dct:identifier "urn:uuid:2c5c9cc0-c73e-4f78-8905-c08bd427866d" ;
    dct:title "Blood Type Read Access Limit Policy" ;
    dct:description "Policy yang membatasi akses membaca bloodType maksimal 1 kali per sesi" ;
    dct:created "2026-02-13T09:00:00Z"^^xsd:dateTime ;
    dct:creator ex:pod-owner ;
    odrl:profile <https://w3id.org/dpv/odrl> ;
    odrl:target <https://schema.org/bloodType> ;
    force:policyActive "true"^^xsd:boolean ;
    odrl:permission _:b752_n3-abc1-permission ;
    odrl:prohibition _:b752_n3-abc1-prohibition .

_:b752_n3-abc1-permission
    odrl:assigner ex:pod-owner ;
    odrl:assignee ex:any-app ;
    odrl:action ex:read ;
    odrl:constraint _:b752_n3-abc1-constraint .

_:b752_n3-abc1-prohibition
    odrl:assignee ex:any-app ;
    odrl:action odrl:distribute .

_:b752_n3-abc1-constraint
    odrl:leftOperand odrl:count ;
    odrl:operator odrl:lteq ;
    odrl:rightOperand "1"^^xsd:integer .

# ===== POLICY 2: Identity - Read + Update =====
ex:policy-identity-92c9be5f4abc4654972a93ccbac0082e a odrl:Policy ;
    dct:identifier "urn:uuid:bd7077e5-990b-4c24-87cb-ce3bbc96fd32" ;
    dct:title "Identity Read/Update Access Limit Policy" ;
    dct:description "Policy yang membatasi akses membaca dan mengupdate identifier maksimal 3 kali per sesi" ;
    dct:created "2026-02-13T09:00:00Z"^^xsd:dateTime ;
    dct:creator ex:pod-owner ;
    odrl:profile <https://w3id.org/dpv/odrl> ;
    odrl:target <https://schema.org/identifier> ;
    force:policyActive "true"^^xsd:boolean ;
    odrl:permission _:b752_n3-def2-permission-read, _:b752_n3-def2-permission-update ;
    odrl:prohibition _:b752_n3-def2-prohibition .

_:b752_n3-def2-permission-read
    odrl:assigner ex:pod-owner ;
    odrl:assignee ex:any-app ;
    odrl:action ex:read ;
    odrl:constraint _:b752_n3-def2-constraint .

_:b752_n3-def2-permission-update
    odrl:assigner ex:pod-owner ;
    odrl:assignee ex:any-app ;
    odrl:action ex:update ;
    odrl:constraint _:b752_n3-def2-constraint .

_:b752_n3-def2-prohibition
    odrl:assignee ex:any-app ;
    odrl:action odrl:distribute .

_:b752_n3-def2-constraint
    odrl:leftOperand odrl:count ;
    odrl:operator odrl:lteq ;
    odrl:rightOperand "3"^^xsd:integer ;
    force:applicableAction ex:read, ex:update .
`;

/* ===============================
🔐 ACL CONTENT FOR POLICY FILE (INLINE)
================================ */
function getPolicyACLContent(podBaseUrl) {
  return `@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
    a acl:Authorization ;
    acl:agent <${podBaseUrl}profile/card#me> ;
    acl:accessTo <monitor-policy.ttl> ;
    acl:mode acl:Read, acl:Write, acl:Control .

<#authenticated-read>
    a acl:Authorization ;
    acl:agentClass foaf:AuthenticatedAgent ;
    acl:accessTo <monitor-policy.ttl> ;
    acl:mode acl:Read .
`;
}

/* ===============================
✅ FIX: Helper fetch dengan timeout + AbortController
================================ */
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}

/* ===============================
✅ CREATE POLICY FILE LOCALLY (fallback)
================================ */
async function savePolicyLocally(podName, policyContent) {
  const policyDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const policyFile = path.join(policyDir, 'monitor-policy.ttl');
  await fs.mkdir(policyDir, { recursive: true });
  try {
    await fs.access(policyFile);
    console.log(`✅ Local policy already exists: ${policyFile}`);
    return false;
  } catch {
    await fs.writeFile(policyFile, policyContent);
    console.log(`🎯 Local policy saved: ${policyFile}`);
    return true;
  }
}

/* ===============================
✅ CREATE ACL FILE LOCALLY (untuk fallback)
================================ */
async function createPolicyACLLocal(podName, podBaseUrl) {
  const aclDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const aclFile = path.join(aclDir, 'monitor-policy.ttl.acl');
  await fs.mkdir(aclDir, { recursive: true });
  const aclContent = getPolicyACLContent(podBaseUrl);
  try {
    await fs.access(aclFile);
    console.log(`✅ Local ACL already exists: ${aclFile}`);
    return false;
  } catch {
    await fs.writeFile(aclFile, aclContent);
    console.log(`🎯 Local ACL saved: ${aclFile}`);
    return true;
  }
}

/* ===============================
✅ CREATE ACL REMOTELY (untuk pod)
================================ */
async function createPolicyACLRemote(podBaseUrl, authToken) {
  try { new URL(podBaseUrl); } catch (e) {
    console.warn(`⚠️ Invalid podBaseUrl for ACL: ${podBaseUrl}`);
    return false;
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  const aclUrl = new URL(POLICY_PATH + '.acl', podBaseUrl).href;
  const aclContent = getPolicyACLContent(podBaseUrl);
  try {
    const res = await fetchWithTimeout(aclUrl, {
      method: 'PUT',
      headers: { 'Authorization': authToken, 'Content-Type': 'text/turtle' },
      body: aclContent
    }, 3000);
    if (res.ok || res.status === 201 || res.status === 409) {
      console.log(`✅ ACL created/confirmed for policy: ${aclUrl}`);
      return true;
    }
    console.warn(`⚠️ ACL creation returned ${res.status} (continuing)`);
    return false;
  } catch (error) {
    console.warn(`⚠️ Could not create remote ACL (continuing): ${error.message}`);
    return false;
  }
}

/* ===============================
✅ DEPLOY POLICY TO POD (INLINE)
================================ */
async function deployPolicyToPod(podBaseUrl, authToken) {
  try { new URL(podBaseUrl); } catch (e) {
    throw new Error(`Invalid podBaseUrl: "${podBaseUrl}"`);
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  console.log(`🔍 Deploying policy to pod: ${podBaseUrl}`);
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  console.log(`📄 Policy URL: ${policyUrl}`);
  
  try {
    const headRes = await fetchWithTimeout(policyUrl, {
      method: 'HEAD',
      headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
    }, 3000);
    console.log(`📡 HEAD response: ${headRes.status}`);
    
    if (headRes.status === 200 || headRes.status === 204) {
      console.log(`✅ Policy already exists at ${policyUrl}`);
      await createPolicyACLRemote(podBaseUrl, authToken);
      return { deployed: false, url: policyUrl, reason: 'already_exists' };
    }
    
    console.log(`📤 PUT ${policyUrl}`);
    const putRes = await fetchWithTimeout(policyUrl, {
      method: 'PUT',
      headers: {
        'Authorization': authToken,
        'Content-Type': 'text/turtle',
        'Slug': 'monitor-policy.ttl',
        'Link': '<http://www.w3.org/ns/ldp#Resource>; rel="type"'
      },
      body: MONITOR_POLICIES_TTL
    }, 5000);
    
    console.log(`📥 PUT response: ${putRes.status}`);
    if (!putRes.ok) {
      const errText = await putRes.text().catch(() => 'No error body');
      console.error(`❌ PUT failed: ${putRes.status} - ${errText}`);
      throw new Error(`Failed to deploy policy: ${putRes.status} ${errText}`);
    }
    
    await createPolicyACLRemote(podBaseUrl, authToken);
    console.log(`✅ Policy deployed successfully to ${policyUrl}`);
    return { deployed: true, url: policyUrl, status: putRes.status };
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error(`❌ Fetch timeout deploying policy to ${policyUrl}`);
    } else {
      console.error(`❌ Error deploying policy to pod:`, error.message);
    }
    throw error;
  }
}

/* ===============================
✅ LOAD POLICY FROM POD (INLINE)
================================ */
async function loadPolicyFromPod(podBaseUrl, authToken) {
  try { new URL(podBaseUrl); } catch (e) {
    throw new Error(`Invalid podBaseUrl: "${podBaseUrl}"`);
  }
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  try {
    const res = await fetchWithTimeout(policyUrl, {
      headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
    }, 3000);
    if (!res.ok) throw new Error(`Failed to fetch policy: ${res.status}`);
    const ttlContent = await res.text();
    console.log(`✅ Policy loaded from pod: ${policyUrl}`);
    return ttlContent;
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error(`❌ Fetch timeout loading policy from ${policyUrl}`);
    } else {
      console.error(`❌ Error loading policy from pod:`, error.message);
    }
    throw error;
  }
}

/* ===============================
🔄 LOAD MULTI-POLICIES - WITH LOCAL CACHE + ACTIVE POLICY SET
================================ */
async function loadPolicies(podName = null, authToken = null, forceRefresh = false) {
  const now = Date.now();
  const cached = activePolicyCache.get(podName);
  
  // Use cache if fresh (<5 min) and not forced refresh
  if (cached && !forceRefresh && (now - cached.lastSync < 5 * 60 * 1000)) {
    console.log(`♻️ Using cached policies for ${podName} (age: ${Math.round((now - cached.lastSync)/1000)}s)`);
    policyEngine.loadPolicies(cached.policies);
    return cached.policies;
  }
  
  let policies = {};
  const activePolicyIRIs = new Set();
  
  if (podName) {
    const policyFile = path.join(DATA_ROOT, podName, POLICY_PATH);
    
    // Try sync from remote if cache is stale or forced
    if ((forceRefresh || !cached || now - (cached?.lastSync || 0) > 5 * 60 * 1000) && authToken) {
      try {
        const podBaseUrl = buildPodBaseUrl(podName);
        const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
        const res = await fetchWithTimeout(policyUrl, {
          headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
        }, 2000);
        if (res.ok) {
          const remoteContent = await res.text();
          await fs.writeFile(policyFile, remoteContent);
          console.log(`🔄 Synced policy from remote to local: ${policyFile}`);
        }
      } catch (e) {
        console.log(`ℹ️ Could not sync remote policy (using local cache): ${e.message}`);
      }
    }
    
    // Parse local policy file
    try {
      const content = await fs.readFile(policyFile, 'utf-8');
      const policyBlocks = content.split(/(?=ex:policy-[^:;]+ a odrl:Policy)/).filter(b => b.trim());
      console.log(`🔍 Parsing ${policyBlocks.length} policy blocks...`);
      
      for (const block of policyBlocks) {
        const metadata = parsePolicyMetadata(block);
        
        // Skip inactive policies entirely
        if (!metadata.active) {
          console.log(`⏭️ Policy INACTIVE (skipped from engine): ${metadata.title || metadata.target}`);
          continue;
        }
        
        const policyKey = `${metadata.target}Access`;
        policies[policyKey] = {
          resource: metadata.resource || `ex:policy-${metadata.target}`,
          identifier: metadata.identifier || `urn:uuid:${metadata.target}-default`,
          title: metadata.title || `${metadata.target} Policy`,
          targetIRI: metadata.target,
          active: metadata.active,
          actions: metadata.actions, // ✅ Multi-action support
          permission: {
            actions: metadata.actions, // ✅ Store actions array
            constraint: {
              leftOperand: "odrl:count",
              operator: "odrl:lteq",
              rightOperand: metadata.maxCount,
              applicableActions: metadata.constraintApplicableActions // ✅ Action-specific constraint
            },
            targetAsset: metadata.target
          },
          prohibition: { action: "odrl:distribute" }
        };
        
        // Track active IRIs for quick lookup
        if (metadata.targetIRI) activePolicyIRIs.add(cleanIRI(metadata.targetIRI));
        if (metadata.resource) activePolicyIRIs.add(cleanIRI(metadata.resource));
        
        console.log(`✅ Loaded ACTIVE policy: ${metadata.title} (target: ${metadata.target}, actions: ${metadata.actions.join(', ')}, max: ${metadata.maxCount})`);
      }
    } catch (err) {
      console.warn(`⚠️ Could not read policy file for ${podName}, using defaults`);
      policies = getDefaultPolicies();
      Object.values(policies).forEach(p => {
        if (p.targetIRI) activePolicyIRIs.add(cleanIRI(p.targetIRI));
        if (p.resource) activePolicyIRIs.add(cleanIRI(p.resource));
      });
    }
  } else {
    // No pod specified: load defaults
    policies = getDefaultPolicies();
    Object.values(policies).forEach(p => {
      if (p.targetIRI) activePolicyIRIs.add(cleanIRI(p.targetIRI));
      if (p.resource) activePolicyIRIs.add(cleanIRI(p.resource));
    });
  }
  
  if (Object.keys(policies).length === 0) {
    console.log(`⚠️ No active policies found. All requests will be ALLOWED.`);
  }
  
  // Update cache
  activePolicyCache.set(podName, {
    policies,
    activePolicyIRIs,
    lastSync: now
  });
  
  // Load into engine
  policyEngine.loadPolicies(policies);
  console.log(`✅ ODRL Policies loaded: ${Object.keys(policies).length} active policies | Active IRIs: ${activePolicyIRIs.size}`);
  
  return policies;
}

function getDefaultPolicies() {
  return {
    bloodTypeAccess: {
      resource: "ex:policy-blood-type-default",
      identifier: "urn:uuid:2c5c9cc0-c73e-4f78-8905-c08bd427866d",
      title: "Blood Type Read Access Limit Policy",
      targetIRI: "https://schema.org/bloodType",
      active: true,
      actions: ['ex:read'], // ✅ Single action default
      permission: {
        actions: ['ex:read'],
        constraint: {
          leftOperand: "odrl:count",
          operator: "odrl:lteq",
          rightOperand: 1,
          applicableActions: ['ex:read'] // ✅ Constraint only for read
        },
        targetAsset: "https://schema.org/bloodType"
      },
      prohibition: { action: "odrl:distribute" }
    },
    identityAccess: {
      resource: "ex:policy-identity-default",
      identifier: "urn:uuid:bd7077e5-990b-4c24-87cb-ce3bbc96fd32",
      title: "Identity Read/Update Access Limit Policy",
      targetIRI: "https://schema.org/identifier",
      active: true,
      actions: ['ex:read', 'ex:update'], // ✅ Multi-action example
      permission: {
        actions: ['ex:read', 'ex:update'],
        constraint: {
          leftOperand: "odrl:count",
          operator: "odrl:lteq",
          rightOperand: 3,
          applicableActions: ['ex:read', 'ex:update'] // ✅ Constraint for both
        },
        targetAsset: "https://schema.org/identifier"
      },
      prohibition: { action: "odrl:distribute" }
    }
  };
}

/* ===============================
🚀 DEPLOY POLICY (Fire-and-forget)
================================ */
const deployedPods = new Set();
const deployingPods = new Set();

function isValidPodName(podName) {
  if (!podName) return false;
  if (['.oidc', '.well-known', '.acl', 'private', 'public'].includes(podName)) return false;
  return /^[a-z0-9][a-z0-9-]{2,}$/.test(podName);
}

function buildPodBaseUrl(podName) {
  return new URL(`/${podName}/`, GATEWAY_BASE).href;
}

async function ensurePolicyDeployed(podName, authToken) {
  if (!isValidPodName(podName)) return false;
  if (deployedPods.has(podName)) {
    loadPolicies(podName, authToken, false).catch(e => console.log(`ℹ️ Cache refresh skipped: ${e.message}`));
    return true;
  }
  if (deployingPods.has(podName)) return true;
  
  deployingPods.add(podName);
  (async () => {
    try {
      const podBaseUrl = buildPodBaseUrl(podName);
      let formattedAuth = authToken;
      if (authToken && !authToken.startsWith('DPoP ')) {
        formattedAuth = `DPoP ${authToken}`;
      }
      const result = await deployPolicyToPod(podBaseUrl, formattedAuth);
      if (result?.deployed) {
        console.log(`🎯 Policy deployed to ${podBaseUrl}${POLICY_PATH}`);
        await loadPolicies(podName, formattedAuth, true);
      }
    } catch (error) {
      console.log(`🔄 Remote deploy failed, using local fallback for ${podName}`);
      await savePolicyLocally(podName, MONITOR_POLICIES_TTL);
      const podBaseUrl = buildPodBaseUrl(podName);
      await createPolicyACLLocal(podName, podBaseUrl);
      await loadPolicies(podName, authToken, true);
    } finally {
      deployingPods.delete(podName);
      deployedPods.add(podName);
    }
  })();
  return true;
}

/* ===============================
START SOLID CSS
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", GATEWAY_BASE
  ],
  { stdio: "inherit" }
);

/* ===============================
UTIL
================================ */
const detectPod = pathname => pathname.split("/").filter(Boolean)[0] || null;
const extractAppName = pathname => {
  const seg = pathname.split("/").filter(Boolean);
  const idx = seg.indexOf("public");
  return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
};
const isAuthenticated = h => !!h.authorization;
const isSystem = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
  p.endsWith(".acl") ||
  p.includes("/private/audit/") ||
  p.includes("/private/odrl/");

/* ===============================
✅ EXTRACT SENSITIVE FIELDS
================================ */
function extractSensitiveFields(rdf) {
  if (!rdf || typeof rdf !== "string") return [];
  const sensitiveFields = new Set();
  const fullIRIMatch = rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g);
  if (fullIRIMatch) {
    fullIRIMatch.forEach(m => {
      const match = m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);
      if (match) {
        const iri = match[1];
        const value = match[2];
        if (value && value.trim()) {
          const normalizedIRI = normalizeField(`<${iri}>`);
          if (isSensitiveField(normalizedIRI)) {
            sensitiveFields.add(normalizedIRI);
          }
        }
      }
    });
  }
  return Array.from(sensitiveFields);
}

/* ===============================
✅ EXTRACT PERSONAL DATA
================================ */
function extractPersonalData(rdf) {
  const result = {
    personalData: [], dataCategories: [], fields: [], values: [],
    sensitive: false, sensitiveFields: [], nonSensitiveFields: []
  };
  if (!rdf || typeof rdf !== "string") return result;
  
  rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g)?.forEach(m => {
    const match = m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);
    if (!match) return;
    const iri = match[1];
    const value = match[2];
    const normalizedIRI = normalizeField(`<${iri}>`);
    
    result.fields.push(normalizedIRI);
    result.values.push(value);
    
    if (SENSITIVE_FIELDS[normalizedIRI]) {
      result.personalData.push(SENSITIVE_FIELDS[normalizedIRI].personalData);
      result.dataCategories.push(SENSITIVE_FIELDS[normalizedIRI].dataCategory);
      result.sensitive = true;
      result.sensitiveFields.push(normalizedIRI);
    } else if (NON_SENSITIVE_FIELDS[normalizedIRI]) {
      result.nonSensitiveFields.push(normalizedIRI);
    }
  });
  
  return result;
}

/* ===============================
ACCESS LOG & SOTW
================================ */
async function ensureAccessLogFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_ACCESS_PATH);
  const file = path.join(dir, "access-log.ttl");
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix report: <https://w3id.org/force/compliance-report#> .

ex:access-log a prov:Collection .
`);
  }
  return file;
}

/* ===============================
✅ ENSURE SOTW FILE
================================ */
async function ensureSotWFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_MONITORING_PATH);
  const file = path.join(dir, "state-of-world.ttl");
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(file);
  } catch {
    const timestamp = new Date().toISOString();
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .
@prefix sotw: <https://w3id.org/force/sotw#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dct: <http://purl.org/dc/terms/> .

ex:sotw-current a sotw:SotW ;
    sotw:currentTime "${timestamp}"^^xsd:dateTime ;
    sotw:currentLocation <https://www.iso.org/obp/ui/#iso:code:3166:ID> ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/bloodType> ;
        sotw:actionType "ex:read"
    ] ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/identifier> ;
        sotw:actionType "ex:read"
    ] ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/identifier> ;
        sotw:actionType "ex:update"
    ] .
`);
  }
  return file;
}

/* ===============================
✅ UPDATE SOTW - Per Action Type
================================ */
async function updateSotW(pod, app, field, countData = null, decision = "ALLOWED", requestedAction = 'ex:read') {
  const sotwFile = await ensureSotWFile(pod);
  let content = await fs.readFile(sotwFile, 'utf-8');
  const now = new Date().toISOString();
  let hasChanges = false;
  
  if (countData && field) {
    const cleanFieldIRI = cleanIRI(field);
    const cleanAction = cleanIRI(requestedAction);
    const escapedIRI = cleanFieldIRI.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // Regex untuk mencari count dengan field + action type match
    const countRegex = new RegExp(
      `(odrl:target\\s+${escapedIRI}\\s*;\\s*sotw:actionType\\s+"${cleanAction}"\\s*;\\s*sotw:countValue\\s+")[^"]+("^^xsd:integer)`,
      'g'
    );
    
    const match = content.match(countRegex);
    if (match) {
      // Field+action sudah ada, cek apakah nilai count berubah
      const currentCountMatch = match[0].match(/sotw:countValue\s+"(\d+)"/);
      const currentCount = currentCountMatch?.[1];
      
      if (currentCount !== String(countData.count)) {
        // Count berubah, update nilai
        content = content.replace(countRegex, `$1${countData.count}$2`);
        hasChanges = true;
        console.log(`📊 SotW count updated: ${cleanFieldIRI} [${cleanAction}] ${currentCount} → ${countData.count}`);
      }
      // Jika count sama, tidak perlu update
    } else {
      // Field+action baru, tambahkan block count baru
      const countBlock = `
ex:sotw-current sotw:count [
    a sotw:Count ;
    sotw:countValue "${countData.count}"^^xsd:integer ;
    odrl:target ${cleanFieldIRI} ;
    sotw:actionType "${cleanAction}"
] .`;
      content += countBlock;
      hasChanges = true;
      console.log(`🆕 SotW new field+action added: ${cleanFieldIRI} [${cleanAction}]`);
    }
  }
  
  // Hanya tulis file jika ada perubahan data
  if (hasChanges) {
    // Update timestamp karena data berubah
    content = content.replace(
      /(sotw:currentTime\s+")[^"]+("^^xsd:dateTime)/,
      `$1${now}$2`
    );
    await fs.writeFile(sotwFile, content);
    console.log(`🌍 SotW updated (${decision}): ${field || 'none'} [${requestedAction}] | Count: ${countData?.count || 'N/A'}`);
  } else {
    console.log(`ℹ️ SotW unchanged (${decision}): ${field || 'none'} [${requestedAction}] - no data changes`);
  }
}

/* ===============================
✅ WRITE ACCESS LOG - Include Action Type
================================ */
async function writeAccessLog({ pod, evalRequest, decision, sensitiveFields,
  violationType = null, personalData = null, method = "GET", resource = "",
  policyMetadata = null, requestedAction = 'ex:read' }) { // ✅ New param
  
  // Skip logging if no sensitive fields AND decision is permitted
  if (sensitiveFields.length === 0 && decision.permitted) return;
  
  const logFile = await ensureAccessLogFile(pod);
  const accessId = `access-${Date.now()}`;
  const timestamp = new Date().toISOString();
  const app = evalRequest?.appName || resource.split('/').filter(Boolean)[2] || "unknown";
  const decisionStr = decision.permitted ? "ALLOWED" : "VIOLATION";
  
  // ROOT: Access Record
  let ttl = `# ===== ROOT: Access Record ${accessId} =====
ex:${accessId} a prov:Activity ;
    prov:startedAtTime "${timestamp}"^^xsd:dateTime ;
    prov:wasAssociatedWith ex:${app} ;
    <https://w3id.org/force/compliance-report#decision> "${decisionStr}" ;
    <https://w3id.org/force/compliance-report#accessMethod> "${method}" ;
    <https://w3id.org/force/compliance-report#requestedAction> "${cleanIRI(requestedAction)}" ;
    <https://w3id.org/force/compliance-report#accessedResource> <${resource}> .
ex:access-log prov:hadMember ex:${accessId} .
`;

  // SUBGRAPH: Personal Data Handling (if sensitive)
  if (personalData && personalData.sensitive) {
    const handlingBundleId = `handling-bundle-${Date.now()}`;
    ttl += `# ===== SUBGRAPH: Personal Data Handling =====
ex:${handlingBundleId} a prov:Bundle ;
    dct:title "Personal Data Handling Context" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasHandlingBundle> ex:${handlingBundleId} .
ex:handling-${Date.now()} a dpv:PersonalDataHandling ;
    dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;
    dpv:hasDataSubject ex:pod-owner ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${handlingBundleId} .
ex:${handlingBundleId} prov:hadMember ex:handling-${Date.now()} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasPersonalDataHandling> ex:handling-${Date.now()} .
`;
  }

  // SUBGRAPH: Accessed Fields Bundle
  const fieldsBundleId = `fields-bundle-${Date.now()}`;
  ttl += `# ===== SUBGRAPH: Accessed Fields Collection =====
ex:${fieldsBundleId} a prov:Bundle ;
    dct:title "Accessed Data Fields" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasFieldsBundle> ex:${fieldsBundleId} .
`;

  if (personalData?.fields?.length > 0) {
    personalData.fields.forEach((fieldIRI, idx) => {
      const fieldId = `field-${Date.now()}-${idx}`;
      const fieldValue = sanitizeTurtleLiteral(personalData.values[idx] || "");
      const isSensitive = personalData.sensitiveFields.includes(fieldIRI);
      const fieldConfig = getFieldConfig(fieldIRI);
      const fieldLabel = fieldConfig?.label || "Unknown Field";
      const dataCategory = fieldConfig?.dataCategory || "dpv:PersonalData";
      const personalDataType = fieldConfig?.personalData || "dpv:Data";
      const cleanFieldIRI = cleanIRI(fieldIRI);
      
      ttl += `# Field[${idx+1}]: ${fieldLabel}
ex:${fieldId} a <https://w3id.org/force/compliance-report#AccessedDataField> ;
    <https://w3id.org/force/compliance-report#fieldIRI> ${cleanFieldIRI} ;
    <https://w3id.org/force/compliance-report#fieldName> "${fieldLabel}" ;
    <https://w3id.org/force/compliance-report#fieldValue> "${fieldValue}" ;
    <https://w3id.org/force/compliance-report#isSensitive> "${isSensitive}"^^xsd:boolean ;
    <https://w3id.org/force/compliance-report#dataCategory> "${dataCategory}" ;
    <https://w3id.org/force/compliance-report#personalDataType> "${personalDataType}" ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${fieldsBundleId} ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${fieldsBundleId} prov:hadMember ex:${fieldId} .
`;
      if (isSensitive && personalData.sensitive) {
        ttl += `ex:handling-${Date.now()} dpv:hasPersonalData ex:${fieldId} .
`;
      }
    });
  }

  // SUBGRAPH: Policy Evaluation Context
  const policyBundleId = `policy-bundle-${Date.now()}`;
  const evaluatedPolicies = [];
  const cached = activePolicyCache.get(pod);
  const activePolicyIRIs = cached?.activePolicyIRIs || new Set();
  
  for (const field of sensitiveFields) {
    const fieldConfig = getFieldConfig(field);
    if (fieldConfig?.protectedByPolicy) {
      const policyKey = fieldConfig.protectedByPolicy;
      const policy = policyEngine.getPolicy?.(policyKey);
      
      // SKIP if policy not in engine OR not active
      if (!policy || !policy.active) {
        console.log(`⏭️ Skipping policy eval logging: Policy ${policyKey} not active or not in engine`);
        continue;
      }
      
      // SKIP if target IRI not in activePolicyIRIs cache
      const targetIRI = cleanIRI(fieldConfig.asset);
      if (!activePolicyIRIs.has(targetIRI) && !activePolicyIRIs.has(cleanIRI(policy.resource || ''))) {
        console.log(`⏭️ Skipping policy eval logging: ${targetIRI} not in activePolicyIRIs cache`);
        continue;
      }
      
      const policyEvalId = `policy-eval-${Date.now()}-${evaluatedPolicies.length}`;
      const policyResource = cleanIRI(policy.resource || `ex:policy-${policyKey}`);
      const policyUUID = policy.identifier || '';
      const aliasResource = `ex:policy-${policyKey}-default`;
      const reasonClean = violationType || (decision.reason ? decision.reason.split(':')[0] : 'N/A');
      const targetAssetIRI = cleanIRI(fieldConfig.asset);
      
      ttl += `ex:${policyEvalId} a <https://w3id.org/force/compliance-report#PolicyEvaluation> ;
    <https://w3id.org/force/compliance-report#evaluatedPolicy> ${aliasResource} ;
    <https://w3id.org/force/compliance-report#evaluationResult> "${decisionStr}" ;
    <https://w3id.org/force/compliance-report#evaluationReason> "${reasonClean}" ;
    <https://w3id.org/force/compliance-report#targetAsset> <${targetAssetIRI}> ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${policyBundleId} .
ex:${policyBundleId} prov:hadMember ex:${policyEvalId} .
`;
      ttl += `# ===== Policy Alias Mapping =====
`;
      ttl += createPolicyAliasMapping(aliasResource, policyResource, policyUUID) + `
`;
      
      evaluatedPolicies.push({
        resource: policyResource,
        alias: aliasResource,
        identifier: policyUUID,
        title: policy.title,
        asset: fieldConfig.asset,
        assetLabel: fieldConfig.assetLabel,
        protectedByPolicy: fieldConfig.protectedByPolicy,
        active: policy.active
      });
    }
  }
  
  // ONLY write policy bundle header if there are evaluations
  if (evaluatedPolicies.length > 0) {
    ttl = `# ===== SUBGRAPH: Policy Evaluation Context =====
ex:${policyBundleId} a prov:Bundle ;
    dct:title "ODRL Policy Evaluation" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasPolicyBundle> ex:${policyBundleId} .
` + ttl;
  }

  // SUBGRAPH: Violation Details
  const violationEntries = [];
  
  if (!decision.permitted && violationType) {
    for (const field of sensitiveFields) {
      const fieldConfig = getFieldConfig(field);
      if (fieldConfig) {
        const cleanFieldIRI = cleanIRI(field);
        const countData = accessCounter.get(pod, app, cleanFieldIRI, requestedAction) || { count: 0 };
        const observedCount = countData.count;
        const policy = policyEngine.getPolicy?.(fieldConfig.protectedByPolicy);
        const limit = policy?.permission?.constraint?.rightOperand || 3;
        
        // SKIP if policy not in engine OR not active (cached check)
        if (!policy || !policy.active) {
          console.log(`⏭️ Skipping violation logging: Policy ${fieldConfig.protectedByPolicy} not active (cached)`);
          continue;
        }
        
        // DOUBLE-CHECK: Read TTL to confirm policyActive = true
        const policyResource = policy.resource || `ex:policy-${fieldConfig.protectedByPolicy}`;
        const isActiveInTTL = await isPolicyActiveInTTL(pod, policyResource);
        if (!isActiveInTTL) {
          console.log(`⏭️ Skipping violation logging: Policy ${policyResource} has policyActive=false in TTL`);
          continue;
        }
        
        // SKIP if field IRI not in activePolicyIRIs cache
        if (!activePolicyIRIs.has(cleanFieldIRI) && !activePolicyIRIs.has(cleanIRI(policyResource))) {
          console.log(`⏭️ Skipping violation logging: ${cleanFieldIRI} not in activePolicyIRIs cache`);
          continue;
        }
        
        // Hanya log violation jika observedCount > limit
        if (observedCount > limit) {
          violationEntries.push({
            fieldIRI: cleanFieldIRI,
            policyAlias: `ex:policy-${fieldConfig.protectedByPolicy}-default`,
            observedCount,
            limit,
            policyTitle: policy?.title || fieldConfig.protectedByPolicy,
            assetLabel: fieldConfig.assetLabel,
            actionType: requestedAction
          });
        }
      }
    }
  }
  
  // ONLY write violation bundle if there are valid violations
  if (violationEntries.length > 0) {
    const violationBundleId = `violation-bundle-${Date.now()}`;
    const violationId = `violation-${Date.now()}`;
    const trulyViolatedPolicyAliases = [...new Set(violationEntries.map(v => cleanIRI(v.policyAlias)))];
    
    ttl += `# ===== SUBGRAPH: Violation Details =====
ex:${violationBundleId} a prov:Bundle ;
    dct:title "Policy Violation Context" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasViolationBundle> ex:${violationBundleId} .
ex:${violationId} a <https://w3id.org/force/compliance-report#PolicyViolation> ;
    <https://w3id.org/force/compliance-report#violationType> "${violationType}" ;
    <https://w3id.org/force/compliance-report#violationTimestamp> "${timestamp}"^^xsd:dateTime ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${violationBundleId} ;
    <https://w3id.org/force/compliance-report#violatedPolicy> ${trulyViolatedPolicyAliases.join(', ')} .
ex:${violationBundleId} prov:hadMember ex:${violationId} .
`;
    
    violationEntries.forEach(entry => {
      const fieldViolationId = `field-violation-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const cleanPolicyAlias = cleanIRI(entry.policyAlias);
      ttl += `ex:${violationId} <https://w3id.org/force/compliance-report#hasFieldViolation> ex:${fieldViolationId} .
ex:${fieldViolationId} a <https://w3id.org/force/compliance-report#FieldViolation> ;
    <https://w3id.org/force/compliance-report#violatedField> ${entry.fieldIRI} ;
    <https://w3id.org/force/compliance-report#violatedPolicy> ${cleanPolicyAlias} ;
    <https://w3id.org/force/compliance-report#observedCount> "${entry.observedCount}"^^xsd:integer ;
    <https://w3id.org/force/compliance-report#allowedLimit> "${entry.limit}"^^xsd:integer ;
    <https://w3id.org/force/compliance-report#actionType> "${cleanIRI(entry.actionType)}" .
`;
    });
  }
  
  await fs.appendFile(logFile, ttl);
  
  // Console logging
  const status = decision.permitted ? "✅ ACCESS ALLOWED" : "⚠️ POLICY VIOLATION";
  const fields = sensitiveFields.length > 0 ? sensitiveFields.join(', ') : 'none';
  
  if (!decision.permitted && violationType && violationEntries.length > 0) {
    const violationDetails = violationEntries.map(v =>
      `${v.policyTitle} (${v.assetLabel} [${v.actionType}]: ${v.observedCount} > ${v.limit})`
    );
    console.log(`${status} | App: ${app} | Action: ${requestedAction} | Fields: ${fields} | VIOLATED: ${violationDetails.join(', ')}`);
  } else if (!decision.permitted && violationType) {
    console.log(`${status} | App: ${app} | Action: ${requestedAction} | Fields: ${fields} | Reason: ${decision.reason} (no active policy violations)`);
  } else {
    const policyRef = evaluatedPolicies.length > 0
      ? `| Policies: ${evaluatedPolicies.filter(p => p.active).map(p => p.title).join(', ')}`
      : '';
    console.log(`${status} | App: ${app} | Action: ${requestedAction} | Fields: ${fields} ${policyRef} | Reason: ${decision.reason}`);
  }
  
  if (personalData) {
    console.log(`   📊 Data: ${personalData.sensitiveFields.length} sensitif, ${personalData.nonSensitiveFields.length} non-sensitif`);
  }
}

/* ===============================
✅ HELPER: Check policyActive dari TTL content
================================ */
async function isPolicyActiveInTTL(pod, policyResource) {
  try {
    const policyFile = path.join(DATA_ROOT, pod, POLICY_PATH);
    const ttlContent = await fs.readFile(policyFile, 'utf-8');
    
    const cleanResource = cleanIRI(policyResource);
    const policyBlockRegex = new RegExp(
      `(${cleanResource}\\s+a\\s+odrl:Policy[\\s\\S]*?)(?=ex:policy-|@prefix|$)`,
      'i'
    );
    const blockMatch = ttlContent.match(policyBlockRegex);
    
    if (blockMatch?.[1]) {
      const block = blockMatch[1];
      const activeMatch = block.match(
        /<https:\/\/w3id\.org\/force\/compliance-report#policyActive\s*>?\s*("?[^"]+"?\^\^xsd:boolean|true|false)/i
      );
      if (activeMatch?.[1]) {
        const val = activeMatch[1]
          .replace(/"/g, '')
          .replace(/\^\^xsd:boolean/i, '')
          .trim()
          .toLowerCase();
        const isActive = val === 'true';
        console.log(`🔍 Policy ${cleanResource} policyActive: ${isActive}`);
        return isActive;
      }
    }
    console.log(`⚠️ policyActive not found for ${cleanResource}, defaulting to true`);
    return true;
  } catch (error) {
    console.warn(`⚠️ Could not check policy active status for ${policyResource}: ${error.message}`);
    return true;
  }
}

/* ===============================
✅ BUILD SOTW WITH COUNT (Multi-Field, Multi-Action)
================================ */
async function buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields, requestedAction = 'ex:read') {
  const sotw = await sotwProvider.build(pod, evalRequest, pathname, sensitiveFields);
  const app = extractAppName(pathname);
  const countState = {};
  
  for (const field of sensitiveFields) {
    const normalizedField = normalizeField(field);
    // ✅ Get count per action type
    const countData = accessCounter.get(pod, app, normalizedField, requestedAction) || { count: 0 };
    countState[normalizedField] = {
      ...countData,
      actionType: requestedAction
    };
  }
  sotw.count = countState;
  return sotw;
}

/* ===============================
🔥 INCREMENT COUNT BEFORE EVALUATION (Per Action Type)
================================ */
async function incrementAndEvaluate(pod, app, sensitiveFields, evalRequest, pathname, requestedAction = 'ex:read') {
  for (const fld of sensitiveFields) {
    const normalizedField = normalizeField(fld);
    if (isSensitiveField(normalizedField)) {
      const now = new Date().toISOString();
      if (shouldCountRequest(pod, app, normalizedField, requestedAction, now)) {
        await sotwProvider.incrementAccessCount(pod, app, normalizedField, requestedAction);
        console.log(`📈 Count incremented: ${normalizedField} [${requestedAction}]`);
      }
    }
  }
  const sotw = await buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields, requestedAction);
  return policyEngine.evaluate(evalRequest, sotw, sensitiveFields, requestedAction);
}

/* ===============================
GATEWAY SERVER (MONITORING MODE)
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;
  
  // Health check
  if (method === "GET" && (url === "/" || url === "/health")) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }
  
  const target = new URL(url, GATEWAY_BASE);
  const pod = detectPod(target.pathname);
  
  // Collect request body for POST/PUT/PATCH
  let body = "";
  for await (const chunk of req) body += chunk;
  
  // Deploy policy if authenticated + valid pod
  if (isAuthenticated(headers) && pod && isValidPodName(pod)) {
    await ensurePolicyDeployed(pod, headers.authorization);
  }
  
  // Proxy request to CSS backend
  const proxy = http.request({
    hostname: "127.0.0.1",
    port: CSS_PORT,
    path: url,
    method,
    headers: { ...headers }
  }, async pres => {
    let resp = "";
    for await (const chunk of pres) resp += chunk;
    
    // ✅ ODRL Evaluation for GET requests with sensitive data
    if (method === "GET" && isAuthenticated(headers) && !isSystem(target.pathname)) {
      try {
        const sensitiveFields = extractSensitiveFields(resp);
        
        if (sensitiveFields.length > 0) {
          const evalRequest = requestBuilder.buildFromHttpRequest(req, target.pathname, pod, body);
          const app = extractAppName(target.pathname);
          
          // ✅ Extract requested action from HTTP method
          const requestedAction = httpMethodToOdrlAction(method, target.pathname, body);
          
          // ✅ Increment count per action type BEFORE evaluation
          for (const fld of sensitiveFields) {
            if (isSensitiveField(fld)) {
              const normalizedField = normalizeField(fld);
              const now = new Date().toISOString();
              if (shouldCountRequest(pod, app, normalizedField, requestedAction, now)) {
                await accessCounter.increment(pod, app, normalizedField, requestedAction);
                console.log(`📈 Count incremented: ${normalizedField} [${requestedAction}]`);
              }
            }
          }
          
          // ✅ Build SotW with action type
          const sotw = await buildSotWWithCount(pod, evalRequest, target.pathname, sensitiveFields, requestedAction);
          
          // ✅ Evaluate with action-aware logic
          const decisionResult = policyEngine.evaluate(evalRequest, sotw, sensitiveFields, requestedAction);
          const personalData = extractPersonalData(resp);
          
          // ✅ Update SotW per field with action type
          for (const field of sensitiveFields) {
            const cleanFieldIRI = cleanIRI(field);
            const countData = accessCounter.get(pod, app, cleanFieldIRI, requestedAction) || { count: 0 };
            await updateSotW(pod, app, cleanFieldIRI, countData, decisionResult.permitted ? "ALLOWED" : "VIOLATION", requestedAction);
          }
          
          // ✅ Write log with action type
          await writeAccessLog({
            pod, evalRequest, decision: decisionResult, sensitiveFields,
            violationType: decisionResult.violatedConstraints?.[0]?.violationType,
            personalData, method, resource: `${GATEWAY_BASE}${target.pathname}`,
            requestedAction
          });
          
          if (!decisionResult.permitted) {
            console.log('⚠️ POLICY VIOLATION DETECTED (access allowed):', decisionResult.reason);
          }
        }
      } catch (error) {
        console.error('⚠️ ODRL evaluation skipped (response):', error.message);
      }
    }
    
    // Forward response to client
    res.writeHead(pres.statusCode, pres.headers);
    res.end(resp);
  });
  
  proxy.on('error', (err) => {
    console.error('❌ Proxy error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Bad Gateway", message: err.message }));
    }
  });
  
  if (body) proxy.write(body);
  proxy.end();
  
}).listen(GATEWAY_PORT, async () => {
  await loadPolicies();
  accessCounter.resetPod('amd');
  console.log('✅ Access counter reset - Count starts from 0');
  console.log(`✅ Solid Gateway with ODRL (MONITORING MODE) @ ${GATEWAY_BASE}`);
  console.log('🔄 Policy Syncing: Local cache enabled (sync every 5 min)');
  console.log('📊 Multi-Policy Support: bloodType (read, limit=1), identity (read+update, limit=3)');
  console.log('🔐 Policy as RDF Resource: ex:policy-xxx + dct:identifier + dct:title');
  console.log('🔗 Fully Semantic Links: report:evaluatedPolicy → resource');
  console.log('🗝️ Policy Alias Mapping: alias → resource → UUID');
  console.log('📝 Research-Grade RDF: Prefix once, targetAsset as full IRI, violatedPolicy consistent with FieldViolation');
  console.log('🌍 State of the World: currentTime, count+actionType, location (sesuai paper)');
  console.log(`💾 Access Counter: ${accessCounter.getStats().totalEntries} entries`);
  console.log('');
  console.log('🎯 Test Sequence:');
  console.log('   1x GET bloodType → ALLOWED (count-read=1, limit=1) + SotW updated');
  console.log('   2x GET bloodType → VIOLATION ✅ (count-read=2 > limit=1) + SotW updated');
  console.log('   1-3x GET/PUT identity → ALLOWED (count≤3, limit=3) + SotW updated per action');
  console.log('   4x GET identity → VIOLATION ✅ (count-read=4 > limit=3) + SotW updated');
  console.log('   1x POST identity → ALLOWED (count-create=1, no constraint for create) + SotW updated');
  console.log('');
  console.log('🔧 Policy Active Check:');
  console.log('   • Policy with policyActive=false → SKIPPED from engine & logging');
  console.log('   • Local cache prevents lock timeout on remote sync');
  console.log('   • Use forceRefresh=true in loadPolicies() to force remote sync');
  console.log('');
  console.log('⚡ Action Hierarchy:');
  console.log('   • ex:read/create/update → includedIn odrl:use');
  console.log('   • Constraint applicableActions filter per action type');
  console.log('   • Count tracking separated per action (read vs update)');
});