import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { VaultController } from './vault.controller';
import { VaultService } from './vault.service';
import { Vault, PinnedCid, PendingUnpin } from './entities';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { TeeModule } from '../tee/tee.module';
import { IpfsProviderModule } from '../ipfs/providers';

@Module({
  imports: [
    TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User, PendingUnpin]),
    ConfigModule,
    TeeModule,
    IpfsProviderModule,
  ],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
