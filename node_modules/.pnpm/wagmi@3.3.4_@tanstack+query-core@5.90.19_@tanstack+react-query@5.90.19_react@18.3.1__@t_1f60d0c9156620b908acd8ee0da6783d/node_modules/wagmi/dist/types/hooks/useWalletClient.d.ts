import type { Config, GetWalletClientErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetWalletClientData, type GetWalletClientOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseWalletClientParameters<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>> = Compute<GetWalletClientOptions<config, chainId, selectData> & ConfigParameter<config>>;
export type UseWalletClientReturnType<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>> = UseQueryReturnType<selectData, GetWalletClientErrorType>;
/** https://wagmi.sh/react/api/hooks/useWalletClient */
export declare function useWalletClient<config extends Config = ResolvedRegister['config'], chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetWalletClientData<config, chainId>>(parameters?: UseWalletClientParameters<config, chainId, selectData>): UseWalletClientReturnType<config, chainId, selectData>;
//# sourceMappingURL=useWalletClient.d.ts.map