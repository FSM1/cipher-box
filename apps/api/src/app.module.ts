import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { RedisModule } from './common/redis.module';
import { HealthModule } from './health/health.module';
import { MetricsModule, HttpMetricsInterceptor } from './metrics';
import { AuthModule } from './auth/auth.module';
import { IpfsModule } from './ipfs/ipfs.module';
import { VaultModule } from './vault/vault.module';
import { IpnsModule } from './ipns/ipns.module';
import { TeeModule } from './tee/tee.module';
import { RepublishModule } from './republish/republish.module';
import { DeviceApprovalModule } from './device-approval/device-approval.module';
import { SharesModule } from './shares/shares.module';
import { MigrationModule } from './migration/migration.module';
import { User } from './auth/entities/user.entity';
import { RefreshToken } from './auth/entities/refresh-token.entity';
import { AuthMethod } from './auth/entities/auth-method.entity';
import { Vault, PinnedCid } from './vault/entities';
import { FolderIpns } from './ipns/entities';
import { TeeKeyState } from './tee/tee-key-state.entity';
import { TeeKeyRotationLog } from './tee/tee-key-rotation-log.entity';
import { IpnsRepublishSchedule } from './republish/republish-schedule.entity';
import { DeviceApproval } from './device-approval/device-approval.entity';
import { Share, ShareKey, ShareInvite } from './shares/entities';
import { PinMigration } from './migration/migration.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // BullMQ global Redis connection for job scheduling
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get('REDIS_HOST', 'localhost'),
          port: config.get<number>('REDIS_PORT', 6379),
          password: config.get('REDIS_PASSWORD', undefined),
        },
      }),
      inject: [ConfigService],
    }),
    // [SECURITY: HIGH-04] Global rate limiting to prevent abuse
    // BypassableThrottlerGuard allows SDK E2E / load tests to skip rate limits
    // via X-Throttle-Bypass header when THROTTLE_BYPASS_SECRET is configured.
    // Bypass is blocked in production (NODE_ENV === 'production').
    // In test mode (NODE_ENV=test), limits are relaxed for browser-based E2E tests
    // which can't set the bypass header.
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const isTest = configService.get<string>('NODE_ENV') === 'test';
        return [
          {
            name: 'short',
            ttl: 1000,
            limit: isTest ? 200 : 10,
          },
          {
            name: 'medium',
            ttl: 60000,
            limit: isTest ? 2000 : 100,
          },
        ];
      },
      inject: [ConfigService],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('DB_HOST', 'localhost'),
        port: configService.get<number>('DB_PORT', 5432),
        username: configService.get<string>('DB_USERNAME', 'postgres'),
        password: configService.get<string>('DB_PASSWORD', 'postgres'),
        database: configService.get<string>('DB_DATABASE', 'cipherbox'),
        entities: [
          User,
          RefreshToken,
          AuthMethod,
          Vault,
          PinnedCid,
          FolderIpns,
          TeeKeyState,
          TeeKeyRotationLog,
          IpnsRepublishSchedule,
          DeviceApproval,
          Share,
          ShareKey,
          ShareInvite,
          PinMigration,
        ],
        synchronize: false,
        migrations: [join(__dirname, 'migrations', '*.js')],
        migrationsRun: true,
        logging:
          configService.get<string>('NODE_ENV') === 'development'
            ? ['error', 'warn', 'migration'] // Dev: errors, warnings, migrations only (no SQL query spam)
            : ['error', 'migration'], // Staging/production: errors and migrations only
      }),
      inject: [ConfigService],
    }),
    RedisModule,
    MetricsModule,
    HealthModule,
    AuthModule,
    IpfsModule.forRootAsync(),
    VaultModule,
    IpnsModule,
    TeeModule,
    RepublishModule,
    DeviceApprovalModule,
    SharesModule,
    MigrationModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useClass: HttpMetricsInterceptor,
    },
  ],
})
export class AppModule {}
