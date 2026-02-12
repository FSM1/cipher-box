import type { Config, GetConnectorClientErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetConnectorClientData, type GetConnectorClientOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseConnectorClientParameters<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>> = Compute<GetConnectorClientOptions<config, chainId, selectData> & ConfigParameter<config>>;
export type UseConnectorClientReturnType<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>> = UseQueryReturnType<selectData, GetConnectorClientErrorType>;
/** https://wagmi.sh/react/api/hooks/useConnectorClient */
export declare function useConnectorClient<config extends Config = ResolvedRegister['config'], chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetConnectorClientData<config, chainId>>(parameters?: UseConnectorClientParameters<config, chainId, selectData>): UseConnectorClientReturnType<config, chainId, selectData>;
//# sourceMappingURL=useConnectorClient.d.ts.map