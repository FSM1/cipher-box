import { StoreType } from './types';
export function isArrayOfStoreType(s) {
    return (s &&
        s.stores &&
        Array.isArray(s.stores) &&
        s.stores.every(function (e) { return Object.values(StoreType).includes(e); }));
}
export function isStoreTypeWithSettings(s) {
    return typeof s === 'object' && s.name !== undefined;
}
//# sourceMappingURL=settings.js.map