"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.applyCookieOptions = exports.initializeStorages = void 0;
var tslib_1 = require("tslib");
var cookieStorage_1 = require("./cookieStorage");
var localStorage_1 = require("./localStorage");
var memoryStorage_1 = require("./memoryStorage");
var settings_1 = require("./settings");
var types_1 = require("./types");
tslib_1.__exportStar(require("./types"), exports);
tslib_1.__exportStar(require("./localStorage"), exports);
tslib_1.__exportStar(require("./cookieStorage"), exports);
tslib_1.__exportStar(require("./memoryStorage"), exports);
tslib_1.__exportStar(require("./universalStorage"), exports);
tslib_1.__exportStar(require("./settings"), exports);
/**
 * Creates multiple storage systems from an array of StoreType and options
 * @param args StoreType and options
 * @returns Storage array
 */
function initializeStorages(args) {
    var storages = args.map(function (s) {
        var type;
        var settings;
        if ((0, settings_1.isStoreTypeWithSettings)(s)) {
            type = s.name;
            settings = s.settings;
        }
        else {
            type = s;
        }
        switch (type) {
            case types_1.StoreType.Cookie:
                return new cookieStorage_1.CookieStorage(settings);
            case types_1.StoreType.LocalStorage:
                return new localStorage_1.LocalStorage();
            case types_1.StoreType.Memory:
                return new memoryStorage_1.MemoryStorage();
            default:
                throw new Error("Unknown Store Type: ".concat(s));
        }
    });
    return storages;
}
exports.initializeStorages = initializeStorages;
/**
 * Injects the CookieOptions into a the arguments for initializeStorage
 * @param storeTypes list of storeType
 * @param cookieOptions cookie Options
 * @returns arguments for initializeStorage
 */
function applyCookieOptions(storeTypes, cookieOptions) {
    return storeTypes.map(function (s) {
        if (cookieOptions && s === types_1.StoreType.Cookie) {
            return {
                name: s,
                settings: cookieOptions,
            };
        }
        return s;
    });
}
exports.applyCookieOptions = applyCookieOptions;
//# sourceMappingURL=index.js.map