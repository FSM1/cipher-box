"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isProcessorCallback = isProcessorCallback;
exports.isAdvancedProcessor = isAdvancedProcessor;
exports.isSeparateProcessor = isSeparateProcessor;
exports.isAdvancedSeparateProcessor = isAdvancedSeparateProcessor;
const url_1 = require("url");
function isProcessorCallback(processor) {
    return 'function' === typeof processor;
}
function isAdvancedProcessor(processor) {
    return ('object' === typeof processor &&
        !!processor.callback &&
        isProcessorCallback(processor.callback));
}
function isSeparateProcessor(processor) {
    return 'string' === typeof processor || processor instanceof url_1.URL;
}
function isAdvancedSeparateProcessor(processor) {
    return ('object' === typeof processor &&
        !!processor.path &&
        isSeparateProcessor(processor.path));
}
