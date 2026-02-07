import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { IPFS_PROVIDER, IpfsProvider, PinataProvider, LocalProvider } from './providers';
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
          useFactory: (configService: ConfigService): IpfsProvider => {
            const provider = configService.get<string>('IPFS_PROVIDER', 'pinata');

            if (provider === 'local') {
              const apiUrl = configService.get<string>(
                'IPFS_LOCAL_API_URL',
                'http://localhost:5001'
              );
              const gatewayUrl = configService.get<string>(
                'IPFS_LOCAL_GATEWAY_URL',
                'http://localhost:8080'
              );
              return new LocalProvider(apiUrl, gatewayUrl);
            }

            const jwt = configService.get<string>('PINATA_JWT');
            if (!jwt) {
              throw new Error(
                'PINATA_JWT environment variable is required when IPFS_PROVIDER=pinata'
              );
            }
            return new PinataProvider(jwt);
          },
          inject: [ConfigService],
        },
      ],
      exports: [IPFS_PROVIDER],
    };
  }
}
