"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseForgotPasswordStore = void 0;
const uuid_1 = require("uuid");
/**
 * A {@link ForgotPasswordStore} using an {@link ExpiringStorage} to hold the necessary records.
 */
class BaseForgotPasswordStore {
    storage;
    ttl;
    constructor(storage, ttl = 15) {
        this.storage = storage;
        this.ttl = ttl * 60 * 1000;
    }
    async generate(email) {
        const recordId = (0, uuid_1.v4)();
        await this.storage.set(recordId, email, this.ttl);
        return recordId;
    }
    async get(recordId) {
        return this.storage.get(recordId);
    }
    async delete(recordId) {
        return this.storage.delete(recordId);
    }
}
exports.BaseForgotPasswordStore = BaseForgotPasswordStore;
//# sourceMappingURL=BaseForgotPasswordStore.js.map