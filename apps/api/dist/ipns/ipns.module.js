"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpnsModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const typeorm_1 = require("@nestjs/typeorm");
const ipns_controller_1 = require("./ipns.controller");
const ipns_service_1 = require("./ipns.service");
const folder_ipns_entity_1 = require("./entities/folder-ipns.entity");
const republish_module_1 = require("../republish/republish.module");
let IpnsModule = class IpnsModule {
};
exports.IpnsModule = IpnsModule;
exports.IpnsModule = IpnsModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule,
            typeorm_1.TypeOrmModule.forFeature([folder_ipns_entity_1.FolderIpns]),
            (0, common_1.forwardRef)(() => republish_module_1.RepublishModule),
        ],
        controllers: [ipns_controller_1.IpnsController],
        providers: [ipns_service_1.IpnsService],
        exports: [ipns_service_1.IpnsService],
    })
], IpnsModule);
//# sourceMappingURL=ipns.module.js.map