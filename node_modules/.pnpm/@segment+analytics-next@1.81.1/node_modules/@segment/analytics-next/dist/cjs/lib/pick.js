"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pick = void 0;
var tslib_1 = require("tslib");
/**
 * @example
 * pick({ 'a': 1, 'b': '2', 'c': 3 }, ['a', 'c'])
 * => { 'a': 1, 'c': 3 }
 */
function pick(object, keys) {
    return Object.assign.apply(Object, tslib_1.__spreadArray([{}], keys.map(function (key) {
        var _a;
        if (object && Object.prototype.hasOwnProperty.call(object, key)) {
            return _a = {}, _a[key] = object[key], _a;
        }
    }), false));
}
exports.pick = pick;
//# sourceMappingURL=pick.js.map