"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.VaultModule = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const config_1 = require("@nestjs/config");
const vault_controller_1 = require("./vault.controller");
const vault_service_1 = require("./vault.service");
const entities_1 = require("./entities");
const folder_ipns_entity_1 = require("../ipns/entities/folder-ipns.entity");
const user_entity_1 = require("../auth/entities/user.entity");
const tee_module_1 = require("../tee/tee.module");
let VaultModule = class VaultModule {
};
exports.VaultModule = VaultModule;
exports.VaultModule = VaultModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([entities_1.Vault, entities_1.PinnedCid, folder_ipns_entity_1.FolderIpns, user_entity_1.User]),
            config_1.ConfigModule,
            tee_module_1.TeeModule,
        ],
        controllers: [vault_controller_1.VaultController],
        providers: [vault_service_1.VaultService],
        exports: [vault_service_1.VaultService],
    })
], VaultModule);
//# sourceMappingURL=vault.module.js.map