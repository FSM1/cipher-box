import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { resolveDbPoolSize } from './common/db-pool';
import { RuntimeModule } from './common/runtime.module';
import { ContentModule } from './content/content.module';
import { DeviceApprovalModule } from './device-approval/device-approval.module';
import { MailboxModule } from './mailbox/mailbox.module';
import { OpsModule } from './ops/ops.module';
import { RegistryModule } from './registry/registry.module';
import { RepublisherModule } from './republisher/republisher.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        host: configService.get<string>('DB_HOST') ?? 'localhost',
        port: Number(configService.get('DB_PORT') ?? 5432),
        username: configService.get<string>('DB_USERNAME') ?? 'postgres',
        password: configService.get<string>('DB_PASSWORD') ?? 'postgres',
        database: configService.get<string>('DB_DATABASE') ?? 'cipherbox',
        autoLoadEntities: true,
        // Schema changes ship as committed migrations only (CI drift-checked).
        synchronize: false,
        uuidExtension: 'pgcrypto' as const,
        // Explicit pool ceiling: the content path derives its pin-admission
        // ceiling from this same value, so a pin burst leaves connections free
        // for other routes.
        extra: { max: resolveDbPoolSize(configService) },
      }),
    }),
    RuntimeModule,
    OpsModule,
    AuthModule,
    MailboxModule,
    RegistryModule,
    ContentModule,
    DeviceApprovalModule,
    RepublisherModule,
  ],
})
export class AppModule {}
