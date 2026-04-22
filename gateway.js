import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

// ODRL Components
import { ODRLPolicyEngine } from './odrl/policy-engine.mjs';
import { EvaluationRequestBuilder } from './odrl/request-builder.mjs';
import { StateOfTheWorldProvider } from './odrl/context-provider.mjs';
import { ComplianceReporter } from './odrl/compliance-reporter.mjs';
import { getAccessCounter } from './odrl/access-counter.mjs';

/* ===============================
   CONFIG (SESUAI RAILWAY)
================================ */
const GATEWAY_PORT = 3000;           // SESUAI RAILWAY
const CSS_PORT = 4000;               // INTERNAL
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app".trim(); // Trim trailing spaces

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_ACCESS_PATH = "private/audit/access";      // Access log (PROV + report)
const AUDIT_MONITORING_PATH = "private/audit/monitoring"; // State of the World
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   SENSITIVE FIELD CONFIGURATION
================================ */
const SENSITIVE_FIELDS = {
  "<https://schema.org/bloodType>": {
    asset: "ex:blood-type",
    label: "Blood Type",
    protectedByPolicy: "bloodTypeAccess",
    personalData: "dpv:HealthData",
    dataCategory: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  }
};

const NON_SENSITIVE_FIELDS = {
  "<http://purl.org/dc/terms/created>": { label: "Created Timestamp", sensitive: false },
  "<https://schema.org/identifier>": { label: "Identifier", sensitive: false }
};

/* ===============================
   ✅ FIELD NORMALIZATION (FIXED)
================================ */
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

/* ===============================
   REQUEST DEDUPLICATION
================================ */
const requestCache = new Map();

function shouldCountRequest(pod, app, field, timestamp) {
  const normalizedField = normalizeField(field);
  const key = `${pod}::${app}::${normalizedField}::${timestamp.substring(0, 19)}`;
  
  if (requestCache.has(key)) {
    console.log(`ℹ️ Skipping duplicate request: ${normalizedField}`);
    return false;
  }
  
  requestCache.set(key, Date.now());
  
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
   LOAD ODRL POLICIES
================================ */
async function loadPolicies() {
  try {
    const policies = {
      bloodTypeAccess: {
        uid: "ex:policy-blood-type",
        permission: {
          action: "odrl:read",
          constraint: {
            leftOperand: "odrl:count",
            operator: "odrl:lteq",
            rightOperand: 3
          },
          targetAsset: "ex:blood-type"
        },
        prohibition: {
          action: "odrl:distribute"
        }
      }
    };
    
    policyEngine.loadPolicies(policies);
    console.log('✅ ODRL Policies loaded (Monitoring Mode)');
    console.log(`   • Blood Type Access: Max 3 accesses`);
    console.log(`   • Mode: MONITORING (violations logged but NOT blocked)`);
    console.log(`   • Base URL: ${PUBLIC_BASE_URL}`);
    
  } catch (error) {
    console.error('❌ Failed to load policies:', error);
    const fallbackPolicies = {
      bloodTypeAccess: {
        uid: "ex:policy-blood-type",
        permission: {
          action: "odrl:read",
          constraint: {
            leftOperand: "odrl:count",
            operator: "odrl:lteq",
            rightOperand: 3
          },
          targetAsset: "ex:blood-type"
        }
      }
    };
    policyEngine.loadPolicies(fallbackPolicies);
  }
}

/* ===============================
   START SOLID CSS (SESUAI RAILWAY CONFIG)
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", PUBLIC_BASE_URL  // SESUAI RAILWAY
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

/* ===============================
   REQUEST FILTERS
================================ */
const isAuthenticated = h => !!h.authorization;
const isProfile = p => p.includes("/profile/card");
const isSystem = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
  p.endsWith(".acl") ||
  p.includes("/private/audit/") ||
  p.includes("/private/odrl/");

const isBrowserNav = h =>
  h["sec-fetch-mode"] === "navigate" ||
  h["sec-fetch-dest"] === "document";

const isApp = h =>
  h["sec-fetch-site"] === "cross-site" ||
  (!!h.authorization && !h["sec-fetch-site"]);

/* ===============================
   ✅ EXTRACT SENSITIVE FIELDS (FIXED)
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
          if (SENSITIVE_FIELDS[normalizedIRI]) {
            sensitiveFields.add(normalizedIRI);
          }
        }
      }
    });
  }
  
  return Array.from(sensitiveFields);
}

/* ===============================
   ✅ EXTRACT PERSONAL DATA (FIXED)
================================ */
function extractPersonalData(rdf, pathname) {
  const result = {
    personalData: [],
    dataCategories: [],
    fields: [],
    values: [],
    sensitive: false,
    sensitiveFields: [],
    nonSensitiveFields: []
  };

  if (!rdf || typeof rdf !== "string") return result;

  /* PREFIXED predicate */
  rdf.match(/([a-zA-Z0-9:_-]+)\s+"([^"]+)"/g)?.forEach(m => {
    const [, field, value] = m.match(/(.+?)\s+"(.+)"/) || [];
    if (!field || !value || field.startsWith("dc:") || field.startsWith("dct:")) return;
    
    result.fields.push(field);
    result.values.push(value);
    
    if (SENSITIVE_FIELDS[field]) {
      result.personalData.push(SENSITIVE_FIELDS[field].personalData);
      result.dataCategories.push(SENSITIVE_FIELDS[field].dataCategory);
      result.sensitive = true;
      result.sensitiveFields.push(field);
    } else if (NON_SENSITIVE_FIELDS[field]) {
      result.nonSensitiveFields.push(field);
    }
  });

  /* FULL IRI predicate */
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
   ACCESS LOG FILE PREP
================================ */
async function ensureAccessLogFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_ACCESS_PATH);
  const file = path.join(dir, "access-log.ttl");

  await fs.mkdir(dir, { recursive: true });

  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(
      file,
`@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix report: <https://w3id.org/force/compliance-report#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix ex: <https://example.org/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

ex:access-log a prov:Collection ;
    dct:title "Access Log for ${pod}'s Health Data" .

`
    );
  }

  return file;
}

/* ===============================
   ✅ STATE OF THE WORLD FILE PREP (FIXED)
================================ */
async function ensureSotWFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_MONITORING_PATH);
  const file = path.join(dir, "state-of-world.ttl");

  await fs.mkdir(dir, { recursive: true });

  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(
      file,
`@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

# This file is continuously updated by monitoring system
ex:sotw-current a :SotW ;
    dct:modified "${new Date().toISOString()}"^^xsd:dateTime ;
    :currentTime "${new Date().toISOString()}"^^xsd:dateTime .

`
    );
  }

  return file;
}

/* ===============================
   ✅ WRITE ACCESS LOG (FIXED)
================================ */
async function writeAccessLog({ 
  pod, evalRequest, decision, sensitiveFields, violationType = null,
  personalData = null, method = "GET", resource = ""
}) {
  if (sensitiveFields.length === 0 && decision.permitted) return;

  const logFile = await ensureAccessLogFile(pod);
  const accessId = `access-${Date.now()}`;
  const timestamp = new Date().toISOString();
  const app = evalRequest?.appName || "unknown-app";
  const purposeConstraint = evalRequest?.context?.find(c => c.leftOperand === 'odrl:purpose');
  const purpose = purposeConstraint?.rightOperand || "dpv:HealthServiceProvision";
  const decisionStr = decision.permitted ? "ALLOWED" : "VIOLATION";
  
  let ttl = `
# Individual access record
ex:${accessId} a prov:Activity ;
    prov:startedAtTime "${timestamp}"^^xsd:dateTime ;
    prov:wasAssociatedWith ex:${app} ;
    prov:used ex:blood-type ;
    ex:action odrl:read ;
    ex:purpose ${purpose} ;
    ex:decision "${decisionStr}" .\n`;
  
  if (!decision.permitted && violationType) {
    ttl += `ex:${accessId} ex:violationType "${violationType}" .\n`;
  }
  
  const reportId = `report-${Date.now()}`;
  ttl += `
ex:${reportId} a report:PolicyReport ;
    dct:created "${timestamp}"^^xsd:dateTime ;
    report:policy ex:policy-blood-type ;
    report:ruleReport ex:rule-report-${reportId} .

ex:rule-report-${reportId} a report:RuleReport ;
    report:rule ex:permission-blood-type ;
    report:activationState report:Active ;
    report:performanceState report:Performed ;
    report:deonticState ${decision.permitted ? "report:Fulfilled" : "report:Violated"} .\n`;
  
  if (personalData && personalData.sensitive) {
    const dpvId = `log-${Date.now()}`;
    ttl += `\n# DPV Personal Data Handling\n`;
    ttl += `${dpvId} a dpv:PersonalDataHandling ;\n`;
    ttl += `  dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;\n`;
    ttl += `  dpv:hasResource <${resource}> ;\n`;
    ttl += `  ex:accessedByApp "${app}" ;\n`;
    ttl += `  ex:containsSensitiveData "${personalData.sensitive}"^^xsd:boolean ;\n`;
    ttl += `  ex:sensitiveFieldCount "${personalData.sensitiveFields.length}"^^xsd:integer ;\n`;
    ttl += `  ex:nonSensitiveFieldCount "${personalData.nonSensitiveFields.length}"^^xsd:integer ;\n`;
    
    personalData.personalData.forEach(p => ttl += `  dpv:hasPersonalData ${p} ;\n`);
    personalData.dataCategories.forEach(c => ttl += `  dpv:hasDataCategory ${c} ;\n`);
    
    personalData.fields.forEach((f, i) => {
      ttl += `  ex:hasDataField "${f}" ;\n`;
      ttl += `  ex:hasDataValue "${personalData.values[i].replace(/"/g, '\\"')}" ;\n`;
    });
    
    ttl += `  dct:created "${timestamp}"^^xsd:dateTime .\n`;
  }
  
  await fs.appendFile(logFile, ttl);
  
  const status = decision.permitted ? "✅ ACCESS ALLOWED" : "⚠️ POLICY VIOLATION (allowed)";
  const fields = sensitiveFields.length > 0 ? sensitiveFields.join(', ') : 'none';
  console.log(`${status} | App: ${app} | Fields: ${fields} | Reason: ${decision.reason}`);
  if (personalData) {
    console.log(`   📊 Data: ${personalData.sensitiveFields.length} sensitif, ${personalData.nonSensitiveFields.length} non-sensitif`);
  }
}

/* ===============================
   ✅ UPDATE STATE OF THE WORLD (CRITICAL FIX)
================================ */
async function updateSotW(pod, app, field, countData = null, decision = "ALLOWED", reason = "") {
  const sotwFile = await ensureSotWFile(pod);
  let content = await fs.readFile(sotwFile, 'utf-8');
  const now = new Date().toISOString();
  
  // Update ex:sotw-current (selalu di-update)
  if (content.includes('ex:sotw-current')) {
    content = content.replace(
      /(ex:sotw-current a :SotW ;\s+dct:modified ")[^"]+/, 
      `$1${now}`
    );
    content = content.replace(
      /(:currentTime ")[^"]+/, 
      `$1${now}`
    );
  } else {
    content += `\nex:sotw-current a :SotW ;\n    dct:modified "${now}"^^xsd:dateTime ;\n    :currentTime "${now}"^^xsd:dateTime .\n`;
  }
  
  // ✅ KRUSIAL: Normalisasi field untuk ex:last-attempt
  const normalizedFieldForLog = field ? normalizeField(field) : 'none';
  const lastAttemptEntry = `
# Latest access attempt
ex:last-attempt a :SotW ;
    :attemptTime "${now}"^^xsd:dateTime ;
    :decision "${decision}" ;
    :reason "${reason.replace(/"/g, '\\"')}" ;
    :field "${normalizedFieldForLog}" .\n`;
  
  if (content.includes('ex:last-attempt')) {
    const lines = content.split('\n');
    const startIndex = lines.findIndex(line => line.includes('ex:last-attempt'));
    if (startIndex !== -1) {
      let endIndex = startIndex + 1;
      while (endIndex < lines.length && lines[endIndex].trim() !== '') endIndex++;
      lines.splice(startIndex, endIndex - startIndex, lastAttemptEntry.trim());
      content = lines.join('\n');
    }
  } else {
    content += '\n' + lastAttemptEntry;
  }
  
  // ✅ Update ex:sotw-blood-type untuk SETIAP akses yang memiliki countData
  if (countData) {
    const sotwEntry = `
# Per-resource tracking
ex:sotw-blood-type a :SotW ;
    :target ex:blood-type ;
    :count "${countData.count}"^^xsd:integer ;
    :lastAccessed "${countData.lastAccess}"^^xsd:dateTime ;
    :firstCollected "${countData.firstAccess}"^^xsd:dateTime .\n`;
    
    if (content.includes('ex:sotw-blood-type')) {
      const lines = content.split('\n');
      const startIndex = lines.findIndex(line => line.includes('ex:sotw-blood-type'));
      if (startIndex !== -1) {
        let endIndex = startIndex + 1;
        while (endIndex < lines.length && lines[endIndex].trim() !== '') endIndex++;
        lines.splice(startIndex, endIndex - startIndex, sotwEntry.trim());
        content = lines.join('\n');
      }
    } else {
      content += '\n' + sotwEntry;
    }
  }
  
  await fs.writeFile(sotwFile, content);
  console.log(`📊 SotW updated (${decision}): ${normalizedFieldForLog} | Count: ${countData?.count || 'N/A'}`);
}

/* ===============================
   ✅ BUILD SOTW WITH COUNT (FIXED)
================================ */
async function buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields) {
  const sotw = await sotwProvider.build(pod, evalRequest, pathname, sensitiveFields);
  const app = extractAppName(pathname);
  const countState = {};
  
  for (const field of sensitiveFields) {
    const normalizedField = normalizeField(field);
    const countData = accessCounter.get(pod, app, normalizedField) || { 
      count: 0, lastAccess: null, firstAccess: null 
    };
    countState[normalizedField] = countData;
  }
  
  sotw.count = countState;
  return sotw;
}

/* ===============================
   GATEWAY SERVER (MONITORING MODE) - SESUAI RAILWAY
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;
  
  /* 🚑 HEALTHCHECK */
  if (method === "GET" && (url === "/" || url === "/health")) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  // Target ke CSS internal (port 4000)
  const target = new URL(url, `http://localhost:${CSS_PORT}`);
  const pod = detectPod(target.pathname);

  let body = "";
  for await (const c of req) body += c;

  // 🔐 ODRL POLICY EVALUATION (PRE-PROXY untuk WRITE)
  if (isAuthenticated(headers) && !isSystem(target.pathname)) {
    try {
      const evalRequest = requestBuilder.buildFromHttpRequest(req, target.pathname, pod);
      const sensitiveFields = ['POST', 'PUT', 'PATCH'].includes(method) 
        ? extractSensitiveFields(body) 
        : [];
      
      if (sensitiveFields.length > 0) {
        const sotw = await buildSotWWithCount(pod, evalRequest, target.pathname, sensitiveFields);
        const decisionResult = policyEngine.evaluate(evalRequest, sotw, sensitiveFields);
        let personalData = extractPersonalData(body, target.pathname);
        
        // Resource URL menggunakan PUBLIC_BASE_URL
        const resourceUrl = `${PUBLIC_BASE_URL}${target.pathname}`;
        
        await writeAccessLog({ 
          pod, evalRequest, decision: decisionResult, sensitiveFields,
          violationType: decisionResult.violatedConstraints[0]?.violationType,
          personalData, method, resource: resourceUrl
        });
        
        const app = extractAppName(target.pathname);
        const normalizedField = normalizeField(sensitiveFields[0]);
        const decisionStr = decisionResult.permitted ? "ALLOWED" : "VIOLATION";
        
        // Update SotW untuk setiap attempt
        await updateSotW(pod, app, normalizedField, null, decisionStr, decisionResult.reason);
        
        if (!decisionResult.permitted) {
          console.log('⚠️ POLICY VIOLATION DETECTED (access allowed):', decisionResult.reason);
        }
        
        // Increment count untuk SEMUA akses (termasuk violation) yang tidak duplicate
        for (const fld of sensitiveFields) {
          const normalizedFld = normalizeField(fld);
          if (SENSITIVE_FIELDS[normalizedFld]) {
            const now = new Date().toISOString();
            const shouldCount = shouldCountRequest(pod, app, normalizedFld, now);
            
            if (shouldCount) {
              const countData = await sotwProvider.incrementAccessCount(pod, app, normalizedFld);
              console.log(`📈 Count incremented: ${normalizedFld} = ${countData.count}`);
              await updateSotW(pod, app, normalizedFld, countData, decisionStr, decisionResult.reason);
            }
          }
        }
      }
      
    } catch (error) {
      console.error('❌ ODRL evaluation error:', error);
    }
  }

  // Proxy ke CSS (port 4000)
  const proxy = http.request(
    { hostname: "localhost", port: CSS_PORT, path: url, method, headers },
    async pres => {
      let resp = "";
      for await (const c of pres) resp += c;

      // 🔐 ODRL EVALUATION untuk GET response (post-proxy)
      if (method === "GET" && isAuthenticated(headers) && !isSystem(target.pathname)) {
        try {
          const evalRequest = requestBuilder.buildFromHttpRequest(req, target.pathname, pod);
          const sensitiveFields = extractSensitiveFields(resp);
          
          if (sensitiveFields.length > 0) {
            const sotw = await buildSotWWithCount(pod, evalRequest, target.pathname, sensitiveFields);
            const decisionResult = policyEngine.evaluate(evalRequest, sotw, sensitiveFields);
            let personalData = extractPersonalData(resp, target.pathname);
            
            // Resource URL menggunakan PUBLIC_BASE_URL
            const resourceUrl = `${PUBLIC_BASE_URL}${target.pathname}`;
            
            await writeAccessLog({ 
              pod, evalRequest, decision: decisionResult, sensitiveFields,
              violationType: decisionResult.violatedConstraints[0]?.violationType,
              personalData, method, resource: resourceUrl
            });
            
            const app = extractAppName(target.pathname);
            const normalizedField = normalizeField(sensitiveFields[0]);
            const decisionStr = decisionResult.permitted ? "ALLOWED" : "VIOLATION";
            
            // Update SotW untuk setiap attempt
            await updateSotW(pod, app, normalizedField, null, decisionStr, decisionResult.reason);
            
            if (!decisionResult.permitted) {
              console.log('⚠️ POLICY VIOLATION DETECTED (access allowed):', decisionResult.reason);
            }
            
            // Increment count untuk SEMUA akses (termasuk violation) yang tidak duplicate
            for (const fld of sensitiveFields) {
              const normalizedFld = normalizeField(fld);
              if (SENSITIVE_FIELDS[normalizedFld]) {
                const now = new Date().toISOString();
                const shouldCount = shouldCountRequest(pod, app, normalizedFld, now);
                
                if (shouldCount) {
                  const countData = await sotwProvider.incrementAccessCount(pod, app, normalizedFld);
                  console.log(`📈 Count incremented: ${normalizedFld} = ${countData.count}`);
                  await updateSotW(pod, app, normalizedFld, countData, decisionStr, decisionResult.reason);
                }
              }
            }
          }
          
        } catch (error) {
          console.error('❌ ODRL evaluation error (response):', error);
        }
      }

      res.writeHead(pres.statusCode, pres.headers);
      res.end(resp);
    }
  );

  if (body) proxy.write(body);
  proxy.end();
}).listen(GATEWAY_PORT, async () => {
  await loadPolicies();
  
  console.log(`\n✅ Solid Gateway with ODRL (MONITORING MODE) @ http://localhost:${GATEWAY_PORT}`);
  console.log(`🌐 Public Base URL: ${PUBLIC_BASE_URL}`);
  console.log(`📊 ODRL Policies Loaded`);
  console.log(`   • Blood Type Access: Max 3 accesses`);
  console.log(`   • Mode: MONITORING (violations logged but NOT blocked)`);
  console.log(`💾 Access Counter: ${accessCounter.getStats().totalEntries} entries\n`);
  
  console.log('🔄 Resetting access counter for testing...');
  accessCounter.resetPod('ayobisa2');
  console.log('✅ Access counter reset - Count starts from 0');
});