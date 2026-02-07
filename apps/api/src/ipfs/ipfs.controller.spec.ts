import { Test, TestingModule } from '@nestjs/testing';
import { PayloadTooLargeException } from '@nestjs/common';
import { IpfsController } from './ipfs.controller';
import { IPFS_PROVIDER, IpfsProvider } from './providers';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { VaultService } from '../vault/vault.service';

describe('IpfsController', () => {
  let controller: IpfsController;
  let ipfsProvider: jest.Mocked<IpfsProvider>;
  let vaultService: jest.Mocked<Pick<VaultService, 'checkQuota' | 'recordPin'>>;

  beforeEach(async () => {
    const mockIpfsProvider: jest.Mocked<IpfsProvider> = {
      pinFile: jest.fn(),
      unpinFile: jest.fn(),
      getFile: jest.fn(),
    };

    const mockVaultService = {
      checkQuota: jest.fn(),
      recordPin: jest.fn(),
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

  describe('add', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;

    it('should call ipfsProvider.pinFile with file.buffer', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        originalname: 'test.enc',
        mimetype: 'application/octet-stream',
        size: 22,
      } as Express.Multer.File;

      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });

      await controller.add(mockFile);

      expect(ipfsProvider.pinFile).toHaveBeenCalledWith(mockFile.buffer);
    });

    it('should return { cid, size }', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        originalname: 'test.enc',
        mimetype: 'application/octet-stream',
        size: 22,
      } as Express.Multer.File;

      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });

      const result = await controller.add(mockFile);

      expect(result).toEqual({ cid: mockCid, size: mockSize });
    });

    it('should pass buffer content correctly', async () => {
      const fileContent = 'encrypted data 12345';
      const mockFile = {
        buffer: Buffer.from(fileContent),
        originalname: 'test.enc',
        mimetype: 'application/octet-stream',
        size: fileContent.length,
      } as Express.Multer.File;

      ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: fileContent.length });

      await controller.add(mockFile);

      const calledBuffer = ipfsProvider.pinFile.mock.calls[0][0];
      expect(calledBuffer.toString()).toBe(fileContent);
    });
  });

  describe('unpin', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';

    it('should call ipfsProvider.unpinFile with dto.cid', async () => {
      const unpinDto = { cid: mockCid };

      ipfsProvider.unpinFile.mockResolvedValue(undefined);

      await controller.unpin(unpinDto);

      expect(ipfsProvider.unpinFile).toHaveBeenCalledWith(mockCid);
    });

    it('should return { success: true }', async () => {
      const unpinDto = { cid: mockCid };

      ipfsProvider.unpinFile.mockResolvedValue(undefined);

      const result = await controller.unpin(unpinDto);

      expect(result).toEqual({ success: true });
    });

    it('should call provider exactly once', async () => {
      const unpinDto = { cid: mockCid };

      ipfsProvider.unpinFile.mockResolvedValue(undefined);

      await controller.unpin(unpinDto);

      expect(ipfsProvider.unpinFile).toHaveBeenCalledTimes(1);
    });
  });

  describe('upload', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;
    const mockReq = { user: { id: 'user-123' } } as any;

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
});
