import { Test, TestingModule } from '@nestjs/testing';
import { IpfsController } from './ipfs.controller';
import { IpfsService } from './ipfs.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

describe('IpfsController', () => {
  let controller: IpfsController;
  let ipfsService: jest.Mocked<IpfsService>;

  beforeEach(async () => {
    const mockIpfsService = {
      pinFile: jest.fn(),
      unpinFile: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IpfsController],
      providers: [
        {
          provide: IpfsService,
          useValue: mockIpfsService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<IpfsController>(IpfsController);
    ipfsService = module.get(IpfsService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('add', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';
    const mockSize = 1024;

    it('should call ipfsService.pinFile with file.buffer', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        originalname: 'test.enc',
        mimetype: 'application/octet-stream',
        size: 22,
      } as Express.Multer.File;

      ipfsService.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });

      await controller.add(mockFile);

      expect(ipfsService.pinFile).toHaveBeenCalledWith(mockFile.buffer);
    });

    it('should return { cid, size }', async () => {
      const mockFile = {
        buffer: Buffer.from('encrypted file content'),
        originalname: 'test.enc',
        mimetype: 'application/octet-stream',
        size: 22,
      } as Express.Multer.File;

      ipfsService.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });

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

      ipfsService.pinFile.mockResolvedValue({ cid: mockCid, size: fileContent.length });

      await controller.add(mockFile);

      const calledBuffer = ipfsService.pinFile.mock.calls[0][0];
      expect(calledBuffer.toString()).toBe(fileContent);
    });
  });

  describe('unpin', () => {
    const mockCid = 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi';

    it('should call ipfsService.unpinFile with dto.cid', async () => {
      const unpinDto = { cid: mockCid };

      ipfsService.unpinFile.mockResolvedValue(undefined);

      await controller.unpin(unpinDto);

      expect(ipfsService.unpinFile).toHaveBeenCalledWith(mockCid);
    });

    it('should return { success: true }', async () => {
      const unpinDto = { cid: mockCid };

      ipfsService.unpinFile.mockResolvedValue(undefined);

      const result = await controller.unpin(unpinDto);

      expect(result).toEqual({ success: true });
    });

    it('should call service exactly once', async () => {
      const unpinDto = { cid: mockCid };

      ipfsService.unpinFile.mockResolvedValue(undefined);

      await controller.unpin(unpinDto);

      expect(ipfsService.unpinFile).toHaveBeenCalledTimes(1);
    });
  });
});
