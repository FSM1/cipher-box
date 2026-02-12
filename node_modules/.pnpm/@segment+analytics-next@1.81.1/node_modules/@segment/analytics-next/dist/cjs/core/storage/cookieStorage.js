"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CookieStorage = void 0;
var tslib_1 = require("tslib");
var js_cookie_1 = tslib_1.__importDefault(require("js-cookie"));
var tld_1 = require("../user/tld");
var ONE_YEAR = 365;
/**
 * Data storage using browser cookies
 */
var CookieStorage = /** @class */ (function () {
    function CookieStorage(options) {
        if (options === void 0) { options = CookieStorage.defaults; }
        this.options = tslib_1.__assign(tslib_1.__assign({}, CookieStorage.defaults), options);
    }
    Object.defineProperty(CookieStorage, "defaults", {
        get: function () {
            return {
                maxage: ONE_YEAR,
                domain: (0, tld_1.tld)(window.location.href),
                path: '/',
                sameSite: 'Lax',
            };
        },
        enumerable: false,
        configurable: true
    });
    CookieStorage.prototype.opts = function () {
        return {
            sameSite: this.options.sameSite,
            expires: this.options.maxage,
            domain: this.options.domain,
            path: this.options.path,
            secure: this.options.secure,
        };
    };
    CookieStorage.prototype.get = function (key) {
        var _a;
        try {
            var value = js_cookie_1.default.get(key);
            if (value === undefined || value === null) {
                return null;
            }
            try {
                return (_a = JSON.parse(value)) !== null && _a !== void 0 ? _a : null;
            }
            catch (e) {
                return (value !== null && value !== void 0 ? value : null);
            }
        }
        catch (e) {
            return null;
        }
    };
    CookieStorage.prototype.set = function (key, value) {
        if (typeof value === 'string') {
            js_cookie_1.default.set(key, value, this.opts());
        }
        else if (value === null) {
            js_cookie_1.default.remove(key, this.opts());
        }
        else {
            js_cookie_1.default.set(key, JSON.stringify(value), this.opts());
        }
    };
    CookieStorage.prototype.remove = function (key) {
        return js_cookie_1.default.remove(key, this.opts());
    };
    return CookieStorage;
}());
exports.CookieStorage = CookieStorage;
//# sourceMappingURL=cookieStorage.js.map