import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { IPFS_PROVIDER } from './ipfs-provider.interface';
import { LocalProvider } from './local.provider';

@Module({
  imports: [ConfigModule],
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
})
export class IpfsProviderModule {}
