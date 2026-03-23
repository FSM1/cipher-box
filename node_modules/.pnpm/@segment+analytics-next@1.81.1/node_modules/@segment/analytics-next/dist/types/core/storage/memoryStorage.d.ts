import { Store, StorageObject } from './types';
/**
 * Data Storage using in memory object
 */
export declare class MemoryStorage<Data extends StorageObject = StorageObject> implements Store<Data> {
    private cache;
    get<K extends keyof Data>(key: K): Data[K] | null;
    set<K extends keyof Data>(key: K, value: Data[K] | null): void;
    remove<K extends keyof Data>(key: K): void;
}
//# sourceMappingURL=memoryStorage.d.ts.map