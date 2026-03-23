import { type Address, type Hex } from "viem";
export type WrapMessageHashParams = {
    accountAddress: Address;
    chainId: number;
};
export declare const wrapMessageHash: (messageHash: Hex, { accountAddress, chainId }: WrapMessageHashParams) => `0x${string}`;
//# sourceMappingURL=wrapMessageHash.d.ts.map