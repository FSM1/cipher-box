import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { IpfsProviderModule } from './ipfs-provider.module';
import { IPFS_PROVIDER } from './ipfs-provider.interface';
import { LocalProvider } from './local.provider';

describe('IpfsProviderModule', () => {
  it('provides and exports IPFS_PROVIDER token as a LocalProvider instance', async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ isGlobal: false }), IpfsProviderModule],
    }).compile();

    const provider = module.get(IPFS_PROVIDER);
    expect(provider).toBeDefined();
    expect(provider).toBeInstanceOf(LocalProvider);
  });
});
