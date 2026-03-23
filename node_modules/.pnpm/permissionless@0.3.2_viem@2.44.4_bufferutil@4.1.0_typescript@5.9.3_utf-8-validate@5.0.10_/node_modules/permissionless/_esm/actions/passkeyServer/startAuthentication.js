import { toHex } from "viem";
import { getOxExports } from "../../utils/ox.js";
export const startAuthentication = async (client) => {
    const response = await client.request({
        method: "pks_startAuthentication",
        params: []
    });
    return {
        challenge: toHex((await getOxExports()).Base64.toBytes(response.challenge)),
        rpId: response.rpId,
        userVerification: response.userVerification,
        uuid: response.uuid
    };
};
//# sourceMappingURL=startAuthentication.js.map