import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { VaultController } from './vault.controller';
import { VaultService } from './vault.service';
import { Vault, PinnedCid } from './entities';

@Module({
  imports: [TypeOrmModule.forFeature([Vault, PinnedCid]), ConfigModule],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
