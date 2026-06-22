import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
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
      // Re-export the imported IpfsProviderModule (which exports IPFS_PROVIDER) so
      // downstream importers like AuthModule can inject the token. A bare
      // `exports: [IPFS_PROVIDER]` fails at boot because the token is not a local
      // provider of IpfsModule — Nest only re-exports a token via its owning module.
      exports: [IpfsProviderModule],
    };
  }
}
