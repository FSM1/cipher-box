import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { buildJwtOptions } from '../auth/auth.module';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AccountController } from './account.controller';
import { NameInventory } from './entities/name-inventory.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { KuboPinStore, PinStore } from './pin-store';
import { RegistryController } from './registry.controller';
import { RegistryService } from './services/registry.service';

/**
 * The pin/name registry slice (blueprint/api.md, Pin/name registry): the
 * register/retire inventory, the per-account quota, and the BYO toggle. Reads
 * the users table for the account BYO flag and quota override; route auth
 * reuses the auth slice's JwtAuthGuard and JWT configuration. The physical
 * unpin is the injectable [`PinStore`] seam (Kubo-backed in a hosted deploy).
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([NameInventory, PinnedCid, User]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: buildJwtOptions,
    }),
  ],
  controllers: [RegistryController, AccountController],
  providers: [RegistryService, JwtAuthGuard, { provide: PinStore, useClass: KuboPinStore }],
})
export class RegistryModule {}
