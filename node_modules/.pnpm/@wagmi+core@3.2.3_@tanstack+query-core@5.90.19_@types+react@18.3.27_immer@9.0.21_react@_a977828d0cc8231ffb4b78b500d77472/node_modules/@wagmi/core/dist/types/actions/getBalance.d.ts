import { type GetBalanceErrorType as viem_GetBalanceErrorType, type GetBalanceParameters as viem_GetBalanceParameters } from 'viem/actions';
import type { Config } from '../createConfig.js';
import type { ChainIdParameter } from '../types/properties.js';
import type { Compute } from '../types/utils.js';
export type GetBalanceParameters<config extends Config = Config> = Compute<ChainIdParameter<config> & viem_GetBalanceParameters>;
export type GetBalanceReturnType = {
    decimals: number;
    symbol: string;
    value: bigint;
};
export type GetBalanceErrorType = viem_GetBalanceErrorType;
/** https://wagmi.sh/core/api/actions/getBalance */
export declare function getBalance<config extends Config>(config: config, parameters: GetBalanceParameters<config>): Promise<GetBalanceReturnType>;
//# sourceMappingURL=getBalance.d.ts.map