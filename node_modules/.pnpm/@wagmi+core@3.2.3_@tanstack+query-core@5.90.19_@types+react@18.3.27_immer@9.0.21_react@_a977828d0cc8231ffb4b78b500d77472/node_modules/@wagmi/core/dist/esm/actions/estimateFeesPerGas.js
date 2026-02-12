import { estimateFeesPerGas as viem_estimateFeesPerGas, } from 'viem/actions';
import { getAction } from '../utils/getAction.js';
export async function estimateFeesPerGas(config, parameters = {}) {
    const { chainId, ...rest } = parameters;
    const client = config.getClient({ chainId });
    const action = getAction(client, viem_estimateFeesPerGas, 'estimateFeesPerGas');
    const { gasPrice, maxFeePerGas, maxPriorityFeePerGas } = await action({
        ...rest,
        chain: client.chain,
    });
    return {
        gasPrice,
        maxFeePerGas,
        maxPriorityFeePerGas,
    };
}
//# sourceMappingURL=estimateFeesPerGas.js.map