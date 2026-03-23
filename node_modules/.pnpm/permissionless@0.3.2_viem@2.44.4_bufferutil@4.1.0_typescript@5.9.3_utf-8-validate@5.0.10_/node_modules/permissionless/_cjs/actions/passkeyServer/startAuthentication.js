"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.startAuthentication = void 0;
const viem_1 = require("viem");
const ox_js_1 = require("../../utils/ox.js");
const startAuthentication = async (client) => {
    const response = await client.request({
        method: "pks_startAuthentication",
        params: []
    });
    return {
        challenge: (0, viem_1.toHex)((await (0, ox_js_1.getOxExports)()).Base64.toBytes(response.challenge)),
        rpId: response.rpId,
        userVerification: response.userVerification,
        uuid: response.uuid
    };
};
exports.startAuthentication = startAuthentication;
//# sourceMappingURL=startAuthentication.js.map