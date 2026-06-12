import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException, PayloadTooLargeException } from '@nestjs/common';
import { Request as ExpressRequest } from 'express';
import { IpfsController } from './ipfs.controller';
import { IPFS_PROVIDER, IpfsProvider } from './providers';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { VaultService } from '../vault/vault.service';
import { MetricsService } from '../metrics/metrics.service';

interface RequestWithUser extends ExpressRequest {
  user: { id: string };
}

describe('IpfsController', () => {
  let controller: IpfsController;
  let ipfsProvider: jest.Mocked<IpfsProvider>;
  let vaultService: jest.Mocked<
    Pick<VaultService, 'checkQuota' | 'recordPin' | 'isUserByo' | 'guardedUnpin'>
  >;
  let mockEndTimer: jest.Mock;
  let mockStartTimer: jest.Mock;

  beforeEach(async () => {
    const mockIpfsProvider: jest.Mocked<IpfsProvider> = {
      pinFile: jest.fn(),
      unpinFile: jest.fn(),
      getFile: jest.fn(),
    };

    const mockVaultService = {
      checkQuota: jest.fn(),
      recordPin: jest.fn(),
      isUserByo: jest.fn(),
      guardedUnpin: jest.fn(),
    };

    mockEndTimer = jest.fn();
    mockStartTimer = jest.fn().mockReturnValue(mockEndTimer);

    const mockMetricsService = {
      fileUploads: { inc: jest.fn() },
      fileUploadBytes: { inc: jest.fn() },
      fileDownloads: { inc: jest.fn() },
      fileUnpins: { inc: jest.fn() },
      ipfsIpnsDuration: { startTimer: mockStartTimer },
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IpfsController],
      providers: [
        {
          provide: IPFS_PROVIDER,
          useValue: mockIpfsProvider,
        },
        {
          provide: VaultService,
          useValue: mockVaultService,
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<IpfsController>(IpfsController);
    ipfsProvider = module.get(IPFS_PROVIDER);
    vaultService = module.get(VaultService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('unpin', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockReq: RequestWithUser = { user: { id: 'userA' } } as RequestWithUser;

    // Test 1: delegates to guardedUnpin with req.user.id; ipfsProvider.unpinFile NOT called
    it('should call vaultService.guardedUnpin with req.user.id and dto.cid', async () => {
      const unpinDto = { cid: mockCid };

      vaultService.guardedUnpin.mockResolvedValue(undefined);

      await controller.unpin(mockReq, unpinDto);

      expect(vaultService.guardedUnpin).toHaveBeenCalledWith('userA', mockCid);
      expect(vaultService.guardedUnpin).toHaveBeenCalledTimes(1);
      expect(ipfsProvider.unpinFile).not.toHaveBeenCalled();
    });

    // Test 2: opaque { success: true } for all outcomes — controller does not branch
    it('should return { success: true } and no additional fields', async () => {
      const unpinDto = { cid: mockCid };

      vaultService.guardedUnpin.mockResolvedValue(undefined);

      const result = await controller.unpin(mockReq, unpinDto);

      expect(result).toStrictEqual({ success: true });
    });
  });

  describe('upload', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;
    const mockReq: RequestWithUser = { user: { id: 'user-123' } } as RequestWithUser;

    // Test 3: happy path unchanged — no guardedUnpin / unpinFile compensation call
    it('should check quota, pin file, record pin, and return result', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });
      vaultService.recordPin.mockResolvedValue(undefined);

      const result = await controller.upload(mockReq, mockFile);

      expect(vaultService.checkQuota).toHaveBeenCalledWith('user-123', 22);
      expect(ipfsProvider.pinFile).toHaveBeenCalledWith(mockFile.buffer);
      expect(vaultService.recordPin).toHaveBeenCalledWith('user-123', mockCid, mockSize);
      expect(vaultService.guardedUnpin).not.toHaveBeenCalled();
      expect(ipfsProvider.unpinFile).not.toHaveBeenCalled();
      expect(result).toEqual({ cid: mockCid, size: mockSize, recorded: true });
    });

    it('should throw PayloadTooLargeException when quota exceeded', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      vaultService.checkQuota.mockResolvedValue(false);

      await expect(controller.upload(mockReq, mockFile)).rejects.toThrow(PayloadTooLargeException);
      expect(ipfsProvider.pinFile).not.toHaveBeenCalled();
      expect(vaultService.recordPin).not.toHaveBeenCalled();
    });

    // Test 4: compensation routes through guardedUnpin, NOT ipfsProvider.unpinFile; original error rethrown
    it('should call guardedUnpin (not ipfsProvider.unpinFile) when recordPin fails', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      const recordPinError = new Error('DB error');
      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });
      vaultService.recordPin.mockRejectedValue(recordPinError);
      vaultService.guardedUnpin.mockResolvedValue(undefined);

      await expect(controller.upload(mockReq, mockFile)).rejects.toThrow('DB error');

      expect(vaultService.guardedUnpin).toHaveBeenCalledWith('user-123', mockCid);
      expect(ipfsProvider.unpinFile).not.toHaveBeenCalled();
    });

    // Test 5: compensation is best-effort — guardedUnpin rejection is swallowed; original error thrown
    it('should rethrow original recordPin error even if guardedUnpin also rejects', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      const recordPinError = new Error('DB error');
      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });
      vaultService.recordPin.mockRejectedValue(recordPinError);
      vaultService.guardedUnpin.mockRejectedValue(new Error('guardedUnpin also failed'));

      const thrown = await controller.upload(mockReq, mockFile).catch((e: unknown) => e);

      expect(thrown).toBe(recordPinError);
      expect((thrown as Error).message).toBe('DB error');
    });

    it('should not record pin if pinFile fails', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockRejectedValue(new Error('IPFS error'));

      await expect(controller.upload(mockReq, mockFile)).rejects.toThrow('IPFS error');
      expect(vaultService.recordPin).not.toHaveBeenCalled();
    });
  });

  describe('get', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockContent = Buffer.from('encrypted file content');

    it('should call ipfsProvider.getFile with cid', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;

      ipfsProvider.getFile.mockResolvedValue(mockContent);

      await controller.get(mockCid, mockRes);

      expect(ipfsProvider.getFile).toHaveBeenCalledWith(mockCid);
    });

    it('should set correct response headers', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;

      ipfsProvider.getFile.mockResolvedValue(mockContent);

      await controller.get(mockCid, mockRes);

      expect(mockRes.set).toHaveBeenCalledWith({
        'Content-Type': 'application/octet-stream',
        'Content-Length': mockContent.length.toString(),
      });
    });

    it('should return a StreamableFile with the buffer', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;

      ipfsProvider.getFile.mockResolvedValue(mockContent);

      const result = await controller.get(mockCid, mockRes);

      expect(result).toBeInstanceOf((await import('@nestjs/common')).StreamableFile);
    });

    it('should call provider exactly once', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;

      ipfsProvider.getFile.mockResolvedValue(mockContent);

      await controller.get(mockCid, mockRes);

      expect(ipfsProvider.getFile).toHaveBeenCalledTimes(1);
    });
  });

  describe('duration instrumentation', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;
    const mockReq: RequestWithUser = { user: { id: 'user-123' } } as RequestWithUser;

    it('should observe pin duration on upload success', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });
      vaultService.recordPin.mockResolvedValue(undefined);

      await controller.upload(mockReq, mockFile);

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'pin', source: '' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success' });
    });

    it('should observe error result when pinFile throws', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        size: 22,
      } as Express.Multer.File;

      vaultService.checkQuota.mockResolvedValue(true);
      ipfsProvider.pinFile.mockRejectedValue(new Error('IPFS error'));

      await expect(controller.upload(mockReq, mockFile)).rejects.toThrow('IPFS error');

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'pin', source: '' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'error' });
    });

    it('should observe cat duration on get success', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;
      const mockContent = Buffer.from('encrypted file content');

      ipfsProvider.getFile.mockResolvedValue(mockContent);

      await controller.get(mockCid, mockRes);

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'cat', source: '' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'success' });
    });

    it('should observe cat error result when getFile throws', async () => {
      const mockRes = {
        set: jest.fn(),
      } as unknown as import('express').Response;

      ipfsProvider.getFile.mockRejectedValue(new Error('IPFS fetch error'));

      await expect(controller.get(mockCid, mockRes)).rejects.toThrow('IPFS fetch error');

      expect(mockStartTimer).toHaveBeenCalledWith({ operation: 'cat', source: '' });
      expect(mockEndTimer).toHaveBeenCalledWith({ result: 'error' });
    });
  });

  describe('registerCid', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSizeBytes = 1024;
    const mockReq: RequestWithUser = { user: { id: 'user-123' } } as RequestWithUser;

    it('should call vaultService.recordPin with correct userId, cid, sizeBytes', async () => {
      vaultService.isUserByo.mockResolvedValue(true);
      vaultService.recordPin.mockResolvedValue(undefined);

      await controller.registerCid(mockReq, { cid: mockCid, sizeBytes: mockSizeBytes });

      expect(vaultService.recordPin).toHaveBeenCalledWith('user-123', mockCid, mockSizeBytes);
    });

    it('should return { recorded: true }', async () => {
      vaultService.isUserByo.mockResolvedValue(true);
      vaultService.recordPin.mockResolvedValue(undefined);

      const result = await controller.registerCid(mockReq, {
        cid: mockCid,
        sizeBytes: mockSizeBytes,
      });

      expect(result).toEqual({ recorded: true });
    });

    it('should reject non-BYO users with ForbiddenException', async () => {
      vaultService.isUserByo.mockResolvedValue(false);

      await expect(
        controller.registerCid(mockReq, { cid: mockCid, sizeBytes: mockSizeBytes })
      ).rejects.toThrow(ForbiddenException);

      expect(vaultService.recordPin).not.toHaveBeenCalled();
    });

    it('should check BYO status before recording pin', async () => {
      vaultService.isUserByo.mockResolvedValue(true);
      vaultService.recordPin.mockResolvedValue(undefined);

      await controller.registerCid(mockReq, { cid: mockCid, sizeBytes: mockSizeBytes });

      expect(vaultService.isUserByo).toHaveBeenCalledWith('user-123');
      expect(vaultService.isUserByo).toHaveBeenCalledTimes(1);
    });

    it('should throw ForbiddenException for non-BYO users', async () => {
      vaultService.isUserByo.mockResolvedValue(false);

      await expect(
        controller.registerCid(mockReq, { cid: mockCid, sizeBytes: mockSizeBytes })
      ).rejects.toThrow(ForbiddenException);

      expect(vaultService.recordPin).not.toHaveBeenCalled();
    });
  });
});
