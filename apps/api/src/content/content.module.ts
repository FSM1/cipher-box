import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { RegistryModule } from '../registry/registry.module';
import { ContentController } from './content.controller';
import { ContentService } from './content.service';

/**
 * The hosted content ingress slice (blueprint/api.md, Content plane). Reuses the
 * registry's pin-store port and `pinned_cids` ledger — an upload registers its
 * pin row in the same traversal as the byte path. Route auth reuses the auth
 * slice's JwtAuthGuard and JWT configuration.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([PinnedCid, User]),
    RegistryModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [ContentController],
  providers: [ContentService, JwtAuthGuard],
})
export class ContentModule {}
