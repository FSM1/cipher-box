"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var IpfsModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpfsModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const providers_1 = require("./providers");
const ipfs_controller_1 = require("./ipfs.controller");
const vault_module_1 = require("../vault/vault.module");
let IpfsModule = IpfsModule_1 = class IpfsModule {
    static forRootAsync() {
        return {
            module: IpfsModule_1,
            imports: [config_1.ConfigModule, vault_module_1.VaultModule],
            controllers: [ipfs_controller_1.IpfsController],
            providers: [
                {
                    provide: providers_1.IPFS_PROVIDER,
                    useFactory: (configService) => {
                        const provider = configService.get('IPFS_PROVIDER', 'pinata');
                        if (provider === 'local') {
                            const apiUrl = configService.get('IPFS_LOCAL_API_URL', 'http://localhost:5001');
                            const gatewayUrl = configService.get('IPFS_LOCAL_GATEWAY_URL', 'http://localhost:8080');
                            return new providers_1.LocalProvider(apiUrl, gatewayUrl);
                        }
                        const jwt = configService.get('PINATA_JWT');
                        if (!jwt) {
                            throw new Error('PINATA_JWT environment variable is required when IPFS_PROVIDER=pinata');
                        }
                        return new providers_1.PinataProvider(jwt);
                    },
                    inject: [config_1.ConfigService],
                },
            ],
            exports: [providers_1.IPFS_PROVIDER],
        };
    }
};
exports.IpfsModule = IpfsModule;
exports.IpfsModule = IpfsModule = IpfsModule_1 = __decorate([
    (0, common_1.Module)({})
], IpfsModule);
//# sourceMappingURL=ipfs.module.js.map