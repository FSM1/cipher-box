import { type QueryKey } from '@tanstack/query-core';
import type { Connector } from '../createConfig.js';
import type { Compute, StrictOmit } from '../types/utils.js';
export declare function structuralSharing<data>(oldData: data | undefined, newData: data): data;
export declare function hashFn(queryKey: QueryKey): string;
export declare function filterQueryOptions<type extends Record<string, unknown> & {
    connector?: Connector | undefined;
}>(options: type): Compute<StrictOmit<type, 'abi' | 'config' | 'connector' | 'query' | 'watch'> & (type extends {
    connector?: Connector | undefined;
} ? {
    connectorUid?: string;
} : unknown)>;
//# sourceMappingURL=utils.d.ts.map