import { deepEqual } from '../utils/deepEqual.js';
import { getConnection } from './getConnection.js';
/** https://wagmi.sh/core/api/actions/watchConnection */
export function watchConnection(config, parameters) {
    const { onChange } = parameters;
    return config.subscribe(() => getConnection(config), onChange, {
        equalityFn(a, b) {
            const { connector: aConnector, ...aRest } = a;
            const { connector: bConnector, ...bRest } = b;
            return (deepEqual(aRest, bRest) &&
                // check connector separately
                aConnector?.id === bConnector?.id &&
                aConnector?.uid === bConnector?.uid);
        },
    });
}
//# sourceMappingURL=watchConnection.js.map