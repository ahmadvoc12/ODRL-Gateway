import fs from "fs/promises";
import path from "path";

/**
 * Persistent Access Counter
 * Tracking berapa kali suatu app mengakses field tertentu
 * Data disimpan di file untuk survive restart
 */
export class AccessCounter {
  constructor(dataRoot) {
    this.dataRoot = dataRoot;
    this.counterFile = path.join(dataRoot, ".odrl-access-counter.json");
    this.counter = new Map(); // key: `${pod}::${app}::${field}`, value: { count, lastAccess, firstAccess }
    this.load();
  }

  /**
   * Load counter dari file (jika ada)
   */
  async load() {
    try {
      const data = await fs.readFile(this.counterFile, 'utf-8');
      const parsed = JSON.parse(data);
      
      // Convert object ke Map
      Object.entries(parsed).forEach(([key, value]) => {
        this.counter.set(key, value);
      });
      
      console.log(`📊 Access Counter loaded: ${this.counter.size} entries`);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('❌ Failed to load access counter:', error);
      }
      // File belum ada, mulai dari kosong
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
      console.error('❌ Failed to save access counter:', error);
    }
  }

  /**
   * Increment access count untuk field tertentu
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name (e.g., "schema:bloodType")
   * @returns {Object} { count, lastAccess, firstAccess }
   */
  async increment(pod, app, field) {
    const key = `${pod}::${app}::${field}`;
    const now = new Date().toISOString();
    
    const current = this.counter.get(key) || { 
      count: 0, 
      lastAccess: null,
      firstAccess: now
    };
    
    current.count += 1;
    current.lastAccess = now;
    this.counter.set(key, current);
    
    // Auto-save setiap increment
    await this.save();
    
    console.log(`📈 Access count incremented: ${key} = ${current.count}`);
    return { ...current };
  }

  /**
   * Get current access count
   * @param {string} pod - Pod name
   * @param {string} app - Application name
   * @param {string} field - Field name
   * @returns {Object} { count, lastAccess, firstAccess } atau null
   */
  get(pod, app, field) {
    const key = `${pod}::${app}::${field}`;
    return this.counter.get(key) || null;
  }

  /**
   * Reset count untuk field tertentu
   */
  async reset(pod, app, field) {
    const key = `${pod}::${app}::${field}`;
    this.counter.delete(key);
    await this.save();
    console.log(`🔄 Access count reset: ${key}`);
  }

  /**
   * Reset semua count untuk pod tertentu
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
    console.log(`🔄 Access count reset for pod: ${pod} (${keysToDelete.length} entries)`);
  }

  /**
   * Get all counts untuk pod
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
   * Generate State of the World RDF untuk field tertentu
   * Sesuai paper: State of the World representation
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