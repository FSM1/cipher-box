"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BullRegistrar = void 0;
const tslib_1 = require("tslib");
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const bull_constants_1 = require("./bull.constants");
const bull_explorer_1 = require("./bull.explorer");
let BullRegistrar = class BullRegistrar {
    constructor(moduleRef, bullExplorer) {
        this.moduleRef = moduleRef;
        this.bullExplorer = bullExplorer;
    }
    onModuleInit() {
        const extraOptions = this.getModuleExtras();
        if (extraOptions?.manualRegistration) {
            return;
        }
        this.register();
    }
    register() {
        return this.bullExplorer.register();
    }
    getModuleExtras() {
        try {
            const extrasToken = bull_constants_1.BULL_EXTRA_OPTIONS_TOKEN;
            return this.moduleRef.get(extrasToken, {
                strict: false,
            });
        }
        catch {
            return null;
        }
    }
};
exports.BullRegistrar = BullRegistrar;
exports.BullRegistrar = BullRegistrar = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [core_1.ModuleRef,
        bull_explorer_1.BullExplorer])
], BullRegistrar);
