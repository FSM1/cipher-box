import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { IPFS_PROVIDER, LocalProvider } from './providers';
import { IpfsController } from './ipfs.controller';
import { VaultModule } from '../vault/vault.module';

@Module({})
export class IpfsModule {
  static forRootAsync(): DynamicModule {
    return {
      module: IpfsModule,
      imports: [ConfigModule, VaultModule],
      controllers: [IpfsController],
      providers: [
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
      exports: [IPFS_PROVIDER],
    };
  }
}
