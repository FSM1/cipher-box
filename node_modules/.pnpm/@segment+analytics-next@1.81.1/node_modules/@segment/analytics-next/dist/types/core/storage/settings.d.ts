import { StoreType, StoreTypeWithSettings } from './types';
export type UniversalStorageSettings = {
    stores: StoreType[];
};
export type StorageSettings = UniversalStorageSettings;
export declare function isArrayOfStoreType(s: StorageSettings): s is UniversalStorageSettings;
export declare function isStoreTypeWithSettings(s: StoreTypeWithSettings | StoreType): s is StoreTypeWithSettings;
//# sourceMappingURL=settings.d.ts.map