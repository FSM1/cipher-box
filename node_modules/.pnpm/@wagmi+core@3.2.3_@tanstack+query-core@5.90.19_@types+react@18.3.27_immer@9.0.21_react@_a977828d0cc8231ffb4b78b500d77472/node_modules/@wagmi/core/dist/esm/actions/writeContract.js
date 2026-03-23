import { writeContract as viem_writeContract, } from 'viem/actions';
import { getAction } from '../utils/getAction.js';
import { getConnectorClient, } from './getConnectorClient.js';
/** https://wagmi.sh/core/api/actions/writeContract */
export async function writeContract(config, parameters) {
    const { account, chainId, connector, ...request } = parameters;
    let client;
    if (typeof account === 'object' && account?.type === 'local')
        client = config.getClient({ chainId });
    else
        client = await getConnectorClient(config, {
            account: account ?? undefined,
            assertChainId: false,
            chainId,
            connector,
        });
    const chain = (() => {
        if (!chainId || client.chain?.id === chainId)
            return client.chain;
        return { id: chainId };
    })();
    const action = getAction(client, viem_writeContract, 'writeContract');
    const hash = await action({
        ...request,
        ...(account ? { account } : {}),
        assertChainId: !!chainId,
        chain,
    });
    return hash;
}
//# sourceMappingURL=writeContract.js.map