import { __assign } from "tslib";
import jar from 'js-cookie';
import { tld } from '../user/tld';
var ONE_YEAR = 365;
/**
 * Data storage using browser cookies
 */
var CookieStorage = /** @class */ (function () {
    function CookieStorage(options) {
        if (options === void 0) { options = CookieStorage.defaults; }
        this.options = __assign(__assign({}, CookieStorage.defaults), options);
    }
    Object.defineProperty(CookieStorage, "defaults", {
        get: function () {
            return {
                maxage: ONE_YEAR,
                domain: tld(window.location.href),
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
            var value = jar.get(key);
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
            jar.set(key, value, this.opts());
        }
        else if (value === null) {
            jar.remove(key, this.opts());
        }
        else {
            jar.set(key, JSON.stringify(value), this.opts());
        }
    };
    CookieStorage.prototype.remove = function (key) {
        return jar.remove(key, this.opts());
    };
    return CookieStorage;
}());
export { CookieStorage };
//# sourceMappingURL=cookieStorage.js.map