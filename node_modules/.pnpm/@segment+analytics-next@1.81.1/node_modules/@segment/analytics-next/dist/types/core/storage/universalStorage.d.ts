import { Store, StorageObject } from './types';
/**
 * Uses multiple storages in a priority list to get/set values in the order they are specified.
 */
export declare class UniversalStorage<Data extends StorageObject = StorageObject> {
    private stores;
    constructor(stores: Store[]);
    get<K extends keyof Data>(key: K): Data[K] | null;
    set<K extends keyof Data>(key: K, value: Data[K] | null): void;
    clear<K extends keyof Data>(key: K): void;
    getAndSync<K extends keyof Data>(key: K): Data[K] | null;
}
//# sourceMappingURL=universalStorage.d.ts.map