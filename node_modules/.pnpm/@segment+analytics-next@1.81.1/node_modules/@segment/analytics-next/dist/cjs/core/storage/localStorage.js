"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalStorage = void 0;
/**
 * Data storage using browser's localStorage
 */
var LocalStorage = /** @class */ (function () {
    function LocalStorage() {
    }
    LocalStorage.prototype.localStorageWarning = function (key, state) {
        console.warn("Unable to access ".concat(key, ", localStorage may be ").concat(state));
    };
    LocalStorage.prototype.get = function (key) {
        var _a;
        try {
            var val = localStorage.getItem(key);
            if (val === null) {
                return null;
            }
            try {
                return (_a = JSON.parse(val)) !== null && _a !== void 0 ? _a : null;
            }
            catch (e) {
                return (val !== null && val !== void 0 ? val : null);
            }
        }
        catch (err) {
            this.localStorageWarning(key, 'unavailable');
            return null;
        }
    };
    LocalStorage.prototype.set = function (key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        }
        catch (_a) {
            this.localStorageWarning(key, 'full');
        }
    };
    LocalStorage.prototype.remove = function (key) {
        try {
            return localStorage.removeItem(key);
        }
        catch (err) {
            this.localStorageWarning(key, 'unavailable');
        }
    };
    return LocalStorage;
}());
exports.LocalStorage = LocalStorage;
//# sourceMappingURL=localStorage.js.map