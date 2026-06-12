import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { VaultController } from './vault.controller';
import { VaultService } from './vault.service';
import { Vault, PinnedCid, PendingUnpin } from './entities';
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
import { User } from '../auth/entities/user.entity';
import { TeeModule } from '../tee/tee.module';
import { IPFS_PROVIDER, LocalProvider } from '../ipfs/providers';

@Module({
  imports: [
    TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User, PendingUnpin]),
    ConfigModule,
    TeeModule,
  ],
  controllers: [VaultController],
  providers: [
    VaultService,
    // Provide IPFS_PROVIDER locally to avoid a circular import with IpfsModule
    // (IpfsModule imports VaultModule — re-importing IpfsModule here would create a cycle)
    {
      provide: IPFS_PROVIDER,
      useFactory: (configService: ConfigService) => {
        const apiUrl = configService.get<string>('IPFS_LOCAL_API_URL', 'http://localhost:5001');
        const gatewayUrl = configService.get<string>(
          'IPFS_LOCAL_GATEWAY_URL',
          'http://localhost:8080'
        );
        return new LocalProvider(apiUrl, gatewayUrl);
      },
      inject: [ConfigService],
    },
  ],
  exports: [VaultService],
})
export class VaultModule {}
