"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProcessorDecoratorService = void 0;
const tslib_1 = require("tslib");
const common_1 = require("@nestjs/common");
let ProcessorDecoratorService = class ProcessorDecoratorService {
    /**
     * Decorates a processor function.
     * This method can be overridden to provide custom behavior for processor decoration.
     *
     * @param processor The processor function to decorate
     * @returns The decorated processor function
     */
    decorate(processor) {
        return processor;
    }
};
exports.ProcessorDecoratorService = ProcessorDecoratorService;
exports.ProcessorDecoratorService = ProcessorDecoratorService = tslib_1.__decorate([
    (0, common_1.Injectable)()
], ProcessorDecoratorService);
