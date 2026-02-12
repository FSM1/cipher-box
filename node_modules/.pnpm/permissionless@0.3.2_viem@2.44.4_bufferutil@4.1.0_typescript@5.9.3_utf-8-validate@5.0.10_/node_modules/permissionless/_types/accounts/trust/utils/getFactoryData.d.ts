import type { Address, Hex } from "viem";
/**
 * Wrapped this function to minimize the call to check if account is deployed
 */
export declare const getFactoryData: ({ bytes, index, secp256k1VerificationFacetAddress }: {
    bytes: Hex;
    index: bigint;
    secp256k1VerificationFacetAddress: Address;
}) => Promise<`0x${string}`>;
//# sourceMappingURL=getFactoryData.d.ts.map