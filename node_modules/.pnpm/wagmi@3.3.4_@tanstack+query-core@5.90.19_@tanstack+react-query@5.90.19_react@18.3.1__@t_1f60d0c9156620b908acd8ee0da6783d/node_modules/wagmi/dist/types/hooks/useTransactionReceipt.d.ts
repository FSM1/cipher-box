import type { Config, GetTransactionReceiptErrorType, ResolvedRegister } from '@wagmi/core';
import type { Compute } from '@wagmi/core/internal';
import { type GetTransactionReceiptData, type GetTransactionReceiptOptions } from '@wagmi/core/query';
import type { ConfigParameter } from '../types/properties.js';
import { type UseQueryReturnType } from '../utils/query.js';
export type UseTransactionReceiptParameters<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>> = Compute<GetTransactionReceiptOptions<config, chainId, selectData> & ConfigParameter<config>>;
export type UseTransactionReceiptReturnType<config extends Config = Config, chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>> = UseQueryReturnType<selectData, GetTransactionReceiptErrorType>;
/** https://wagmi.sh/react/api/hooks/useTransactionReceipt */
export declare function useTransactionReceipt<config extends Config = ResolvedRegister['config'], chainId extends config['chains'][number]['id'] = config['chains'][number]['id'], selectData = GetTransactionReceiptData<config, chainId>>(parameters?: UseTransactionReceiptParameters<config, chainId, selectData>): UseTransactionReceiptReturnType<config, chainId, selectData>;
//# sourceMappingURL=useTransactionReceipt.d.ts.map