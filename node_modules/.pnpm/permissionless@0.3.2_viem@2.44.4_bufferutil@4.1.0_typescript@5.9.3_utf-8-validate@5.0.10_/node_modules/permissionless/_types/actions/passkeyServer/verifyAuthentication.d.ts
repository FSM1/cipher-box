import type { Account, Chain, Client, Hex, Transport } from "viem";
import type { PasskeyServerRpcSchema } from "../../types/passkeyServer.js";
export type VerifyAuthenticationParameters = {
    raw: {
        id: string;
        rawId: ArrayBuffer;
        authenticatorAttachment: string;
        response: {
            authenticatorData?: ArrayBuffer;
            signature?: ArrayBuffer;
            userHandle?: ArrayBuffer;
            clientDataJSON: ArrayBuffer;
        };
        getClientExtensionResults: () => Record<string, unknown>;
        type: string;
    };
    uuid: string;
};
export type VerifyAuthenticationReturnType = {
    success: boolean;
    id: string;
    publicKey: Hex;
    userName: string;
};
export declare const verifyAuthentication: (client: Client<Transport, Chain | undefined, Account | undefined, PasskeyServerRpcSchema>, args: VerifyAuthenticationParameters) => Promise<VerifyAuthenticationReturnType>;
//# sourceMappingURL=verifyAuthentication.d.ts.map