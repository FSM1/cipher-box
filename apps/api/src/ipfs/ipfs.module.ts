import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { IPFS_PROVIDER } from './providers';
import { IpfsProviderModule } from './providers';
import { IpfsController } from './ipfs.controller';
import { VaultModule } from '../vault/vault.module';

@Module({})
export class IpfsModule {
  static forRootAsync(): DynamicModule {
    return {
      module: IpfsModule,
      imports: [ConfigModule, VaultModule, IpfsProviderModule],
      controllers: [IpfsController],
      providers: [],
      exports: [IPFS_PROVIDER],
    };
  }
}
