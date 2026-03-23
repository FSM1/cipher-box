import type { Config } from '../createConfig.js';
import { type GetConnectionReturnType } from './getConnection.js';
export type WatchConnectionParameters<config extends Config = Config> = {
    onChange(connection: GetConnectionReturnType<config>, prevConnection: GetConnectionReturnType<config>): void;
};
export type WatchConnectionReturnType = () => void;
/** https://wagmi.sh/core/api/actions/watchConnection */
export declare function watchConnection<config extends Config>(config: config, parameters: WatchConnectionParameters<config>): WatchConnectionReturnType;
//# sourceMappingURL=watchConnection.d.ts.map