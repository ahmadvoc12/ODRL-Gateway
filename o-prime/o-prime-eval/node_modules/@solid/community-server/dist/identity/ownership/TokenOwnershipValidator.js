"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenOwnershipValidator = void 0;
const n3_1 = require("n3");
const uuid_1 = require("uuid");
const LogUtil_1 = require("../../logging/LogUtil");
const BadRequestHttpError_1 = require("../../util/errors/BadRequestHttpError");
const HttpErrorUtil_1 = require("../../util/errors/HttpErrorUtil");
const FetchUtil_1 = require("../../util/FetchUtil");
const Vocabularies_1 = require("../../util/Vocabularies");
const OwnershipValidator_1 = require("./OwnershipValidator");
const { literal, namedNode, quad } = n3_1.DataFactory;
/**
 * Validates ownership of a WebId by seeing if a specific triple can be added.
 * `expiration` parameter is how long the token should be valid in minutes.
 */
class TokenOwnershipValidator extends OwnershipValidator_1.OwnershipValidator {
    logger = (0, LogUtil_1.getLoggerFor)(this);
    storage;
    expiration;
    constructor(storage, expiration = 30) {
        super();
        this.storage = storage;
        // Convert minutes to milliseconds
        this.expiration = expiration * 60 * 1000;
    }
    async handle({ webId }) {
        const key = this.getTokenKey(webId);
        let token = await this.storage.get(key);
        // No reason to fetch the WebId if we don't have a token yet
        if (!token) {
            token = this.generateToken();
            await this.storage.set(key, token, this.expiration);
            this.throwError(webId, token);
        }
        // Verify if the token can be found in the WebId
        if (!await this.hasToken(webId, token)) {
            this.throwError(webId, token);
        }
        this.logger.debug(`Verified ownership of ${webId}`);
        await this.storage.delete(key);
    }
    /**
     * Creates a key to use with the token storage.
     */
    getTokenKey(webId) {
        return encodeURIComponent(webId);
    }
    /**
     * Generates a random verification token;
     */
    generateToken() {
        return (0, uuid_1.v4)();
    }
    /**
     * Fetches data from the WebID to determine if the token is present.
     */
    async hasToken(webId, token) {
        const representation = await (0, FetchUtil_1.fetchDataset)(webId);
        const expectedQuad = quad(namedNode(webId), Vocabularies_1.SOLID.terms.oidcIssuerRegistrationToken, literal(token));
        for await (const data of representation.data) {
            const triple = data;
            if (triple.equals(expectedQuad)) {
                representation.data.destroy();
                return true;
            }
        }
        return false;
    }
    /**
     * Throws an error containing the description of which triple is needed for verification.
     */
    throwError(webId, token) {
        this.logger.debug(`No verification token found for ${webId}`);
        const errorMessage = [
            'Verification token not found.',
            'Please add the RDF triple',
            `<${webId}> <${Vocabularies_1.SOLID.oidcIssuerRegistrationToken}> "${token}".`,
            `to the WebID document at ${webId.replace(/#.*/u, '')}`,
            'to prove it belongs to you.',
            'You can remove this triple again after validation.',
        ].join(' ');
        const details = { quad: `<${webId}> <${Vocabularies_1.SOLID.oidcIssuerRegistrationToken}> "${token}".` };
        throw new BadRequestHttpError_1.BadRequestHttpError(errorMessage, { metadata: (0, HttpErrorUtil_1.errorTermsToMetadata)(details) });
    }
}
exports.TokenOwnershipValidator = TokenOwnershipValidator;
//# sourceMappingURL=TokenOwnershipValidator.js.map