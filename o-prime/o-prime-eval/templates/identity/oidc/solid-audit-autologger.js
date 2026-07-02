/**
 * SOLID DPV AUDIT AUTO LOGGER
 * -----------------------------------
 * Triggered after successful consent redirect.
 * Reads consent payload from sessionStorage
 * Writes dpv:PersonalDataHandling log into user's POD
 *
 * Location created:
 *   /private/audit/access/<timestamp>.ttl
 */

(async () => {
  try {
    /* =====================================================
     * 1. LOAD CONSENT PAYLOAD (FROM CONSENT UI)
     * ===================================================== */
    const raw = sessionStorage.getItem("solidPendingConsent");
    if (!raw) {
      console.debug("[DPV] No pending consent found");
      return;
    }

    // Cleanup immediately to avoid duplicate logs
    sessionStorage.removeItem("solidPendingConsent");

    const consent = JSON.parse(raw);

    if (!consent.webId || !consent.client) {
      console.warn("[DPV] Invalid consent payload");
      return;
    }

    /* =====================================================
     * 2. PREPARE POD PATH
     * ===================================================== */
    const podRoot = consent.webId.replace(/\/profile\/card#me$/, "/");

    const timestamp = new Date().toISOString();
    const safeTs = timestamp.replace(/[:.]/g, "-");

    const logPath =
      podRoot +
      "private/audit/access/" +
      safeTs +
      ".ttl";

    /* =====================================================
     * 3. PREPARE PERSONAL DATA LIST
     * ===================================================== */
    let personalDataTTL = "dpv:NonPersonalData";

    if (Array.isArray(consent.personalData) && consent.personalData.length > 0) {
      personalDataTTL = consent.personalData
        .map(d => d.category || "dpv:PersonalData")
        .join(", ");
    }

    /* =====================================================
     * 4. BUILD RDF/TURTLE LOG
     * ===================================================== */
    const turtle = `
@prefix dpv:    <https://www.w3.org/ns/dpv#> .
@prefix dpv-pd: <https://www.w3.org/ns/dpv/pd#> .
@prefix dct:    <http://purl.org/dc/terms/> .
@prefix ex:     <https://example.org/solid/audit#> .

ex:log-${safeTs}
  a dpv:PersonalDataHandling ;
  dpv:hasDataSubject <${consent.webId}> ;
  dpv:hasDataController <${consent.client}> ;
  dpv:hasPersonalData ${personalDataTTL} ;
  dpv:hasProcessing ${
    consent.monitoring ? "dpv:Monitoring" : "dpv:Access"
  } ;
  dpv:hasLegalBasis dpv:ExplicitConsent ;
  ex:monitoringEnabled "${consent.monitoring}"^^<http://www.w3.org/2001/XMLSchema#boolean> ;
  ex:dataStored "false"^^<http://www.w3.org/2001/XMLSchema#boolean> ;
  dct:created "${timestamp}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;

    /* =====================================================
     * 5. WRITE LOG INTO POD
     * ===================================================== */
    const res = await fetch(logPath, {
      method: "PUT",
      headers: {
        "Content-Type": "text/turtle"
      },
      body: turtle
    });

    if (!res.ok) {
      console.error("[DPV] Failed to write audit log", res.status);
      return;
    }

    console.info("[DPV] Audit log created:", logPath);

  } catch (err) {
    console.error("[DPV] Audit logger error:", err);
  }
})();