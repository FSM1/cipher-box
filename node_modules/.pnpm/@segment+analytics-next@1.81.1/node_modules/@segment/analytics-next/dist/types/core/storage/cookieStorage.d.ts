import { Store, StorageObject } from './types';
export interface CookieOptions {
    maxage?: number;
    domain?: string;
    path?: string;
    secure?: boolean;
    sameSite?: string;
}
/**
 * Data storage using browser cookies
 */
export declare class CookieStorage<Data extends StorageObject = StorageObject> implements Store<Data> {
    static get defaults(): CookieOptions;
    private options;
    constructor(options?: CookieOptions);
    private opts;
    get<K extends keyof Data>(key: K): Data[K] | null;
    set<K extends keyof Data>(key: K, value: Data[K] | null): void;
    remove<K extends keyof Data>(key: K): void;
}
//# sourceMappingURL=cookieStorage.d.ts.map