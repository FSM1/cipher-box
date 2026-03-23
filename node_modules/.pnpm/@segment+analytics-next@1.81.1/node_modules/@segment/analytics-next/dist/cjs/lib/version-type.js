"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getVersionType = exports.setVersionType = void 0;
// Default value will be updated to 'web' in `bundle-umd.ts` for web build.
var _version = 'npm';
function setVersionType(version) {
    _version = version;
}
exports.setVersionType = setVersionType;
function getVersionType() {
    return _version;
}
exports.getVersionType = getVersionType;
//# sourceMappingURL=version-type.js.map