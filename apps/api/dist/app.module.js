"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const typeorm_1 = require("@nestjs/typeorm");
const bullmq_1 = require("@nestjs/bullmq");
const throttler_1 = require("@nestjs/throttler");
const app_controller_1 = require("./app.controller");
const app_service_1 = require("./app.service");
const health_module_1 = require("./health/health.module");
const auth_module_1 = require("./auth/auth.module");
const ipfs_module_1 = require("./ipfs/ipfs.module");
const vault_module_1 = require("./vault/vault.module");
const ipns_module_1 = require("./ipns/ipns.module");
const tee_module_1 = require("./tee/tee.module");
const republish_module_1 = require("./republish/republish.module");
const user_entity_1 = require("./auth/entities/user.entity");
const refresh_token_entity_1 = require("./auth/entities/refresh-token.entity");
const auth_method_entity_1 = require("./auth/entities/auth-method.entity");
const entities_1 = require("./vault/entities");
const entities_2 = require("./ipns/entities");
const tee_key_state_entity_1 = require("./tee/tee-key-state.entity");
const tee_key_rotation_log_entity_1 = require("./tee/tee-key-rotation-log.entity");
const republish_schedule_entity_1 = require("./republish/republish-schedule.entity");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true,
            }),
            // BullMQ global Redis connection for job scheduling
            bullmq_1.BullModule.forRootAsync({
                imports: [config_1.ConfigModule],
                useFactory: (config) => ({
                    connection: {
                        host: config.get('REDIS_HOST', 'localhost'),
                        port: config.get('REDIS_PORT', 6379),
                        password: config.get('REDIS_PASSWORD', undefined),
                    },
                }),
                inject: [config_1.ConfigService],
            }),
            // [SECURITY: HIGH-04] Global rate limiting to prevent abuse
            throttler_1.ThrottlerModule.forRoot([
                {
                    name: 'short',
                    ttl: 1000, // 1 second
                    limit: 10, // 10 requests per second
                },
                {
                    name: 'medium',
                    ttl: 60000, // 1 minute
                    limit: 100, // 100 requests per minute
                },
            ]),
            typeorm_1.TypeOrmModule.forRootAsync({
                imports: [config_1.ConfigModule],
                useFactory: (configService) => ({
                    type: 'postgres',
                    host: configService.get('DB_HOST', 'localhost'),
                    port: configService.get('DB_PORT', 5432),
                    username: configService.get('DB_USERNAME', 'postgres'),
                    password: configService.get('DB_PASSWORD', 'postgres'),
                    database: configService.get('DB_DATABASE', 'cipherbox'),
                    entities: [
                        user_entity_1.User,
                        refresh_token_entity_1.RefreshToken,
                        auth_method_entity_1.AuthMethod,
                        entities_1.Vault,
                        entities_1.PinnedCid,
                        entities_2.FolderIpns,
                        tee_key_state_entity_1.TeeKeyState,
                        tee_key_rotation_log_entity_1.TeeKeyRotationLog,
                        republish_schedule_entity_1.IpnsRepublishSchedule,
                    ],
                    synchronize: ['development', 'test'].includes(configService.get('NODE_ENV', 'development')),
                    logging: configService.get('NODE_ENV') === 'development'
                        ? ['error', 'warn', 'migration'] // Dev: errors, warnings, migrations only (no SQL query spam)
                        : ['error', 'migration'], // Staging/production: errors and migrations only
                }),
                inject: [config_1.ConfigService],
            }),
            health_module_1.HealthModule,
            auth_module_1.AuthModule,
            ipfs_module_1.IpfsModule.forRootAsync(),
            vault_module_1.VaultModule,
            ipns_module_1.IpnsModule,
            tee_module_1.TeeModule,
            republish_module_1.RepublishModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService],
    })
], AppModule);
//# sourceMappingURL=app.module.js.map