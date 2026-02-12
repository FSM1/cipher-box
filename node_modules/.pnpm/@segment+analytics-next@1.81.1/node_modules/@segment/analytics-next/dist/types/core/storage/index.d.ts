import { CookieOptions } from './cookieStorage';
import { StoreType, Store, InitializeStorageArgs } from './types';
export * from './types';
export * from './localStorage';
export * from './cookieStorage';
export * from './memoryStorage';
export * from './universalStorage';
export * from './settings';
/**
 * Creates multiple storage systems from an array of StoreType and options
 * @param args StoreType and options
 * @returns Storage array
 */
export declare function initializeStorages(args: InitializeStorageArgs): Store[];
/**
 * Injects the CookieOptions into a the arguments for initializeStorage
 * @param storeTypes list of storeType
 * @param cookieOptions cookie Options
 * @returns arguments for initializeStorage
 */
export declare function applyCookieOptions(storeTypes: StoreType[], cookieOptions?: CookieOptions): InitializeStorageArgs;
//# sourceMappingURL=index.d.ts.map