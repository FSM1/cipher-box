import { type VerifyMessageErrorType, type VerifyMessageParameters, type VerifyMessageReturnType } from '../actions/verifyMessage.js';
import type { Config } from '../createConfig.js';
import type { ScopeKeyParameter } from '../types/properties.js';
import type { QueryOptions, QueryParameter } from '../types/query.js';
import type { Compute, ExactPartial } from '../types/utils.js';
export type VerifyMessageOptions<config extends Config, selectData = VerifyMessageData> = Compute<ExactPartial<VerifyMessageParameters<config>> & ScopeKeyParameter> & QueryParameter<VerifyMessageQueryFnData, VerifyMessageErrorType, selectData, VerifyMessageQueryKey<config>>;
export declare function verifyMessageQueryOptions<config extends Config, selectData = VerifyMessageData>(config: config, options?: VerifyMessageOptions<config, selectData>): VerifyMessageQueryOptions<config, selectData>;
export type VerifyMessageQueryFnData = VerifyMessageReturnType;
export type VerifyMessageData = VerifyMessageQueryFnData;
export declare function verifyMessageQueryKey<config extends Config>(options?: Compute<ExactPartial<VerifyMessageParameters<config>> & ScopeKeyParameter>): readonly ["verifyMessage", {
    chainId?: config["chains"][number]["id"] | (config["chains"][number]["id"] extends infer T ? T extends config["chains"][number]["id"] ? T extends config["chains"][number]["id"] ? T : undefined : never : never) | undefined;
    message?: import("viem").SignableMessage | undefined;
    address?: `0x${string}` | undefined;
    chain?: import("viem").Chain | null | undefined;
    blockNumber?: bigint | undefined | undefined;
    factory?: `0x${string}` | undefined;
    factoryData?: `0x${string}` | undefined;
    signature?: `0x${string}` | import("viem").ByteArray | import("viem").Signature | undefined;
    blockTag?: import("viem").BlockTag | undefined;
    erc6492VerifierAddress?: `0x${string}` | undefined;
    multicallAddress?: `0x${string}` | undefined;
    universalSignatureVerifierAddress?: `0x${string}` | undefined;
    scopeKey?: string | undefined | undefined;
}];
export type VerifyMessageQueryKey<config extends Config> = ReturnType<typeof verifyMessageQueryKey<config>>;
export type VerifyMessageQueryOptions<config extends Config, selectData = VerifyMessageData> = QueryOptions<VerifyMessageQueryFnData, VerifyMessageErrorType, selectData, VerifyMessageQueryKey<config>>;
//# sourceMappingURL=verifyMessage.d.ts.map