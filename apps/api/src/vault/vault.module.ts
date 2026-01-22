import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { VaultController } from './vault.controller';
import { VaultService } from './vault.service';
import { Vault, PinnedCid } from './entities';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns]), ConfigModule],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
