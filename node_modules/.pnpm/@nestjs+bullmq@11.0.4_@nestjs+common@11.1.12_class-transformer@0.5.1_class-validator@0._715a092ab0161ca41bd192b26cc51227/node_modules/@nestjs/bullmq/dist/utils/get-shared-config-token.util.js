"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BULL_CONFIG_DEFAULT_TOKEN = void 0;
exports.getSharedConfigToken = getSharedConfigToken;
exports.BULL_CONFIG_DEFAULT_TOKEN = 'BULLMQ_CONFIG(default)';
function getSharedConfigToken(configKey) {
    return configKey ? `BULLMQ_CONFIG(${configKey})` : exports.BULL_CONFIG_DEFAULT_TOKEN;
}
