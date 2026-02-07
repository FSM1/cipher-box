import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { HealthModule } from './health/health.module';
import { AuthModule } from './auth/auth.module';
import { IpfsModule } from './ipfs/ipfs.module';
import { VaultModule } from './vault/vault.module';
import { IpnsModule } from './ipns/ipns.module';
import { TeeModule } from './tee/tee.module';
import { User } from './auth/entities/user.entity';
import { RefreshToken } from './auth/entities/refresh-token.entity';
import { AuthMethod } from './auth/entities/auth-method.entity';
import { Vault, PinnedCid } from './vault/entities';
import { FolderIpns } from './ipns/entities';
import { TeeKeyState } from './tee/tee-key-state.entity';
import { TeeKeyRotationLog } from './tee/tee-key-rotation-log.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // [SECURITY: HIGH-04] Global rate limiting to prevent abuse
    ThrottlerModule.forRoot([
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
        ],
        synchronize: configService.get<string>('NODE_ENV') !== 'production',
        logging: configService.get<string>('NODE_ENV') === 'development',
      }),
      inject: [ConfigService],
    }),
    HealthModule,
    AuthModule,
    IpfsModule.forRootAsync(),
    VaultModule,
    IpnsModule,
    TeeModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
