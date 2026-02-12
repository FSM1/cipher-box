"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isStoreTypeWithSettings = exports.isArrayOfStoreType = void 0;
var types_1 = require("./types");
function isArrayOfStoreType(s) {
    return (s &&
        s.stores &&
        Array.isArray(s.stores) &&
        s.stores.every(function (e) { return Object.values(types_1.StoreType).includes(e); }));
}
exports.isArrayOfStoreType = isArrayOfStoreType;
function isStoreTypeWithSettings(s) {
    return typeof s === 'object' && s.name !== undefined;
}
exports.isStoreTypeWithSettings = isStoreTypeWithSettings;
//# sourceMappingURL=settings.js.map