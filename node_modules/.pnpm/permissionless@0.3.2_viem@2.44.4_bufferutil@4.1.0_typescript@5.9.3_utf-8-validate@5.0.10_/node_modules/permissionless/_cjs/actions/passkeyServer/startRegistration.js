"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.startRegistration = void 0;
const ox_js_1 = require("../../utils/ox.js");
const validateAttestation = (attestation) => {
    return (!!attestation &&
        ["direct", "enterprise", "indirect", "none"].includes(attestation));
};
const validateAuthenticatorSelection = (authenticatorSelection) => {
    if (!authenticatorSelection)
        return false;
    const validAttachments = ["platform", "cross-platform"];
    const validKeyOptions = new Set(["required", "preferred", "discouraged"]);
    return (validAttachments.includes(authenticatorSelection.authenticatorAttachment) &&
        typeof authenticatorSelection.requireResidentKey === "boolean" &&
        validKeyOptions.has(authenticatorSelection.residentKey) &&
        validKeyOptions.has(authenticatorSelection.userVerification));
};
const validateChallenge = (challenge) => {
    return !!challenge && typeof challenge === "string";
};
const validateExtensions = (extensions) => {
    if (!extensions)
        return true;
    if (typeof extensions !== "object")
        return false;
    const ext = extensions;
    if ("appid" in ext && typeof ext.appid !== "string")
        return false;
    if ("credProps" in ext && typeof ext.credProps !== "boolean")
        return false;
    if ("hmacCreateSecret" in ext && typeof ext.hmacCreateSecret !== "boolean")
        return false;
    if ("minPinLength" in ext && typeof ext.minPinLength !== "boolean")
        return false;
    return true;
};
const validateRp = (rp) => {
    return !!rp && typeof rp.id === "string" && typeof rp.name === "string";
};
const validateUser = (user) => {
    return (!!user &&
        typeof user.id === "string" &&
        typeof user.name === "string" &&
        typeof user.displayName === "string");
};
const startRegistration = async (client, args) => {
    const response = await client.request({
        method: "pks_startRegistration",
        params: [args?.context]
    });
    if (!validateAttestation(response.attestation) ||
        !validateAuthenticatorSelection(response.authenticatorSelection) ||
        !validateChallenge(response.challenge) ||
        !validateExtensions(response.extensions) ||
        !validateRp(response.rp) ||
        !validateUser(response.user)) {
        throw new Error("Invalid response format from passkey server");
    }
    const { Base64 } = await (0, ox_js_1.getOxExports)();
    const credentialOptions = {
        attestation: response.attestation,
        authenticatorSelection: response.authenticatorSelection,
        challenge: Base64.toBytes(response.challenge),
        extensions: response.extensions
            ? {
                ...response.extensions
            }
            : undefined,
        rp: response.rp,
        timeout: response.timeout,
        user: {
            id: Base64.toBytes(response.user.id),
            name: response.user.name,
            displayName: response.user.displayName
        }
    };
    return credentialOptions;
};
exports.startRegistration = startRegistration;
//# sourceMappingURL=startRegistration.js.map