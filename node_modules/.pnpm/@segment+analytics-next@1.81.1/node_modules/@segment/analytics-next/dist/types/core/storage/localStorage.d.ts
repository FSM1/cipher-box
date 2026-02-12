import { StorageObject, Store } from './types';
/**
 * Data storage using browser's localStorage
 */
export declare class LocalStorage<Data extends StorageObject = StorageObject> implements Store<Data> {
    private localStorageWarning;
    get<K extends keyof Data>(key: K): Data[K] | null;
    set<K extends keyof Data>(key: K, value: Data[K] | null): void;
    remove<K extends keyof Data>(key: K): void;
}
//# sourceMappingURL=localStorage.d.ts.map