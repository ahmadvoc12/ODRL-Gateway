import fs from "fs/promises";
import path from "path";

/**
 * Persistent Access Counter
 * Tracks how many times an app accesses a specific field
 * Data is stored in a file to survive restarts
 */
export class AccessCounter {
  constructor(dataRoot) {
    this.dataRoot = dataRoot;
    this.counterFile = path.join(dataRoot, ".odrl-access-counter.json");
    this.counter = new Map(); // key: `${pod}::${app}::${field}`, value: { count, lastAccess, firstAccess }
    this.load();
  }

  /**
   * Load the counter from file (if present)
   */
  async load() {
    try {
      const data = await fs.readFile(this.counterFile, 'utf-8');
      const parsed = JSON.parse(data);

      // Convert object ke Map
      Object.entries(parsed).forEach(([key, value]) => {
        this.counter.set(key, value);
      });

      console.log(`Access Counter loaded: ${this.counter.size} entries`);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('Failed to load access counter:', error);
      }
      // File does not exist yet; start from empty
    }
  }

  /**
   * Save counter ke file
   */
  async save() {
    try {
      // Convert Map ke object
      const data = Object.fromEntries(this.counter);
      await fs.writeFile(this.counterFile, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Failed to save access counter:', error);
    }
  }

  /**
   * Build the per-(pod, app, field, action) key. The action is included so that read
   * and write usage counts on the SAME field stay separate (e.g. ex:read vs ex:update).
   * Callers that omit the action get the legacy action-less key.
   */
  _key(pod, app, field, action) {
    return action ? `${pod}::${app}::${field}::${action}` : `${pod}::${app}::${field}`;
  }

  /**
   * Increment the access count for a specific field + action
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name (e.g., "schema:bloodType")
   * @param {string} action - ODRL action (ex:read | ex:create | ex:update | ...)
   * @returns {Object} { count, lastAccess, firstAccess }
   */
  async increment(pod, app, field, action = null) {
    const key = this._key(pod, app, field, action);
    const now = new Date().toISOString();

    const current = this.counter.get(key) || {
      count: 0,
      lastAccess: null,
      firstAccess: now
    };

    current.count += 1;
    current.lastAccess = now;
    this.counter.set(key, current);

    // Auto-save on every increment
    await this.save();

    console.log(`Access count incremented: ${key} = ${current.count}`);
    return { ...current };
  }

  /**
   * Get current access count
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name
   * @returns {Object} { count, lastAccess, firstAccess } or null
   */
  get(pod, app, field, action = null) {
    const key = this._key(pod, app, field, action);
    return this.counter.get(key) || null;
  }

  /**
   * Reset the count for a specific field (+ action when given)
   */
  async reset(pod, app, field, action = null) {
    const key = this._key(pod, app, field, action);
    this.counter.delete(key);
    await this.save();
    console.log(`Access count reset: ${key}`);
  }

  /**
   * Reset all counts for a specific pod
   */
  async resetPod(pod) {
    const keysToDelete = [];
    for (const key of this.counter.keys()) {
      if (key.startsWith(`${pod}::`)) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => this.counter.delete(key));
    await this.save();
    console.log(`Access count reset for pod: ${pod} (${keysToDelete.length} entries)`);
  }

  /**
   * Get all counts for a pod
   */
  getAllForPod(pod) {
    const result = {};
    for (const [key, value] of this.counter.entries()) {
      if (key.startsWith(`${pod}::`)) {
        result[key] = value;
      }
    }
    return result;
  }

  /**
   * Get statistik lengkap
   */
  getStats() {
    return {
      totalEntries: this.counter.size,
      entries: Object.fromEntries(this.counter)
    };
  }

  /**
   * Generate State of the World RDF for a specific field
   * Per the paper: State of the World representation
   */
  toSotWRDF(pod, app, field) {
    const data = this.get(pod, app, field);
    if (!data) return null;

    const sotwId = `sotw-${pod}-${app}-${field.replace(/[:/]/g, '-')}`;

    return `
@prefix : <https://w3id.org/force/sotw#> .
@prefix ex: <https://example.org/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dct: <http://purl.org/dc/terms/> .

:${sotwId} a :SotW ;
    dct:modified "${new Date().toISOString()}"^^xsd:dateTime ;
    :currentTime "${new Date().toISOString()}"^^xsd:dateTime .

:${sotwId}-blood-type a :SotW ;
    :target ex:blood-type ;
    :count "${data.count}"^^xsd:integer ;
    :lastAccessed "${data.lastAccess}"^^xsd:dateTime ;
    :firstCollected "${data.firstAccess}"^^xsd:dateTime .`;
  }
}

// Export singleton instance
let singletonInstance = null;

export function getAccessCounter(dataRoot) {
  if (!singletonInstance) {
    singletonInstance = new AccessCounter(dataRoot);
  }
  return singletonInstance;
}