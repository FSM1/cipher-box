import { Injectable, Inject, Module } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { IpfsProviderModule } from './ipfs-provider.module';
import { IPFS_PROVIDER, IpfsProvider } from './ipfs-provider.interface';
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

  // Regression for the boot-time UnknownExportException: a module that imports
  // IpfsProviderModule cannot re-export IPFS_PROVIDER directly (the token is not
  // its own local provider) — it must re-export the IpfsProviderModule itself for
  // a downstream importer (e.g. AuthModule) to inject the token. This mirrors the
  // IpfsModule.forRootAsync() -> AuthModule injection chain that failed at boot
  // when exports was `[IPFS_PROVIDER]` instead of `[IpfsProviderModule]`.
  it('re-exports IPFS_PROVIDER to a downstream importer via module re-export', async () => {
    // Mirrors IpfsModule.forRootAsync(): imports the leaf, re-exports the module.
    @Module({
      imports: [IpfsProviderModule],
      exports: [IpfsProviderModule],
    })
    class ReExportingModule {}

    // Mirrors AuthService: a consumer in a separate module that injects the token.
    @Injectable()
    class ConsumerService {
      constructor(@Inject(IPFS_PROVIDER) public readonly ipfs: IpfsProvider) {}
    }

    @Module({
      imports: [ReExportingModule],
      providers: [ConsumerService],
    })
    class ConsumerModule {}

    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ isGlobal: false }), ConsumerModule],
    }).compile();

    const consumer = module.get(ConsumerService);
    expect(consumer.ipfs).toBeInstanceOf(LocalProvider);
  });
});
