import { OnModuleInit } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { BullExplorer } from './bull.explorer';
export declare class BullRegistrar implements OnModuleInit {
    private readonly moduleRef;
    private readonly bullExplorer;
    constructor(moduleRef: ModuleRef, bullExplorer: BullExplorer);
    onModuleInit(): void;
    register(): void;
    private getModuleExtras;
}
//# sourceMappingURL=bull.registrar.d.ts.map