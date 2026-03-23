import { getBalance as viem_getBalance, } from 'viem/actions';
import { getAction } from '../utils/getAction.js';
/** https://wagmi.sh/core/api/actions/getBalance */
export async function getBalance(config, parameters) {
    const { address, blockNumber, blockTag, chainId } = parameters;
    const client = config.getClient({ chainId });
    const action = getAction(client, viem_getBalance, 'getBalance');
    const value = await action(blockNumber ? { address, blockNumber } : { address, blockTag });
    const chain = config.chains.find((x) => x.id === chainId) ?? client.chain;
    return {
        decimals: chain.nativeCurrency.decimals,
        symbol: chain.nativeCurrency.symbol,
        value,
    };
}
//# sourceMappingURL=getBalance.js.map