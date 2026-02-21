import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { VaultController } from './vault.controller';
import { VaultService } from './vault.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { InitVaultDto } from './dto/init-vault.dto';

describe('VaultController', () => {
  let controller: VaultController;
  let vaultService: jest.Mocked<VaultService>;

  const mockUser = {
    id: 'user-uuid-123',
  };

  const mockVaultResponse = {
    id: 'vault-uuid-123',
    ownerPublicKey: '04abcd1234567890',
    encryptedRootFolderKey: 'encrypted-folder-key-hex',
    encryptedRootIpnsPrivateKey: 'encrypted-ipns-key-hex',
    rootIpnsName: 'k51qzi5uqu5test',
    createdAt: new Date('2026-01-20T00:00:00Z'),
    initializedAt: null,
    teeKeys: null,
  };

  beforeEach(async () => {
    const mockVaultService = {
      initializeVault: jest.fn(),
      findVault: jest.fn(),
      getVault: jest.fn(),
      getQuota: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [VaultController],
      providers: [
        {
          provide: VaultService,
          useValue: mockVaultService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<VaultController>(VaultController);
    vaultService = module.get(VaultService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('initializeVault', () => {
    const initVaultDto: InitVaultDto = {
      ownerPublicKey: '04abcd1234567890',
      encryptedRootFolderKey: 'encrypted-folder-key-hex',
      encryptedRootIpnsPrivateKey: 'encrypted-ipns-key-hex',
      rootIpnsName: 'k51qzi5uqu5test',
    };

    it('should call vaultService.initializeVault with user.id and dto', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.initializeVault.mockResolvedValue(mockVaultResponse);

      await controller.initializeVault(mockRequest, initVaultDto);

      expect(vaultService.initializeVault).toHaveBeenCalledWith('user-uuid-123', initVaultDto);
    });

    it('should return vault response', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.initializeVault.mockResolvedValue(mockVaultResponse);

      const result = await controller.initializeVault(mockRequest, initVaultDto);

      expect(result).toEqual(mockVaultResponse);
    });
  });

  describe('getVault', () => {
    it('should call vaultService.findVault with user.id', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.findVault.mockResolvedValue(mockVaultResponse);

      await controller.getVault(mockRequest);

      expect(vaultService.findVault).toHaveBeenCalledWith('user-uuid-123');
    });

    it('should throw NotFoundException if vault is null', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.findVault.mockResolvedValue(null);

      await expect(controller.getVault(mockRequest)).rejects.toThrow(NotFoundException);
      await expect(controller.getVault(mockRequest)).rejects.toThrow('Vault not found');
    });

    it('should return vault response if found', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.findVault.mockResolvedValue(mockVaultResponse);

      const result = await controller.getVault(mockRequest);

      expect(result).toEqual(mockVaultResponse);
    });
  });

  describe('getQuota', () => {
    const mockQuotaResponse = {
      usedBytes: 1000000,
      limitBytes: 524288000,
      remainingBytes: 523288000,
    };

    it('should call vaultService.getQuota with user.id', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.getQuota.mockResolvedValue(mockQuotaResponse);

      await controller.getQuota(mockRequest);

      expect(vaultService.getQuota).toHaveBeenCalledWith('user-uuid-123');
    });

    it('should return quota response', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      vaultService.getQuota.mockResolvedValue(mockQuotaResponse);

      const result = await controller.getQuota(mockRequest);

      expect(result).toEqual(mockQuotaResponse);
    });
  });
});
