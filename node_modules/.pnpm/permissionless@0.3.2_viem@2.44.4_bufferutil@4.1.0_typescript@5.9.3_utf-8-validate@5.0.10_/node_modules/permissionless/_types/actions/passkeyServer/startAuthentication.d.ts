import { type Account, type Chain, type Client, type Transport } from "viem";
import type { PasskeyServerRpcSchema } from "../../types/passkeyServer.js";
export type StartAuthenticationReturnType = {
    challenge: string;
    rpId: string;
    userVerification?: string;
    uuid: string;
};
export declare const startAuthentication: (client: Client<Transport, Chain | undefined, Account | undefined, PasskeyServerRpcSchema>) => Promise<StartAuthenticationReturnType>;
//# sourceMappingURL=startAuthentication.d.ts.map