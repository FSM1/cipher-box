"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UniversalStorage = void 0;
// not adding to private method because those method names do not get minified atm, and does not use 'this'
var _logStoreKeyError = function (store, action, key, err) {
    console.warn("".concat(store.constructor.name, ": Can't ").concat(action, " key \"").concat(key, "\" | Err: ").concat(err));
};
/**
 * Uses multiple storages in a priority list to get/set values in the order they are specified.
 */
var UniversalStorage = /** @class */ (function () {
    function UniversalStorage(stores) {
        this.stores = stores;
    }
    UniversalStorage.prototype.get = function (key) {
        var val = null;
        for (var _i = 0, _a = this.stores; _i < _a.length; _i++) {
            var store = _a[_i];
            try {
                val = store.get(key);
                if (val !== undefined && val !== null) {
                    return val;
                }
            }
            catch (e) {
                _logStoreKeyError(store, 'get', key, e);
            }
        }
        return null;
    };
    UniversalStorage.prototype.set = function (key, value) {
        this.stores.forEach(function (store) {
            try {
                store.set(key, value);
            }
            catch (e) {
                _logStoreKeyError(store, 'set', key, e);
            }
        });
    };
    UniversalStorage.prototype.clear = function (key) {
        this.stores.forEach(function (store) {
            try {
                store.remove(key);
            }
            catch (e) {
                _logStoreKeyError(store, 'remove', key, e);
            }
        });
    };
    /*
      This is to support few scenarios where:
      - value exist in one of the stores ( as a result of other stores being cleared from browser ) and we want to resync them
      - read values in AJS 1.0 format ( for customers after 1.0 --> 2.0 migration ) and then re-write them in AJS 2.0 format
    */
    UniversalStorage.prototype.getAndSync = function (key) {
        var val = this.get(key);
        // legacy behavior, getAndSync can change the type of a value from number to string (AJS 1.0 stores numerical values as a number)
        var coercedValue = (typeof val === 'number' ? val.toString() : val);
        this.set(key, coercedValue);
        return coercedValue;
    };
    return UniversalStorage;
}());
exports.UniversalStorage = UniversalStorage;
//# sourceMappingURL=universalStorage.js.map