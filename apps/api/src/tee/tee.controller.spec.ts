import { Test, TestingModule } from '@nestjs/testing';
import { TeeController } from './tee.controller';
import { TeeService } from './tee.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ConnectionTestRequestDto, ConnectionTestResponseDto } from './dto/connection-test.dto';

describe('TeeController', () => {
  let controller: TeeController;
  let teeService: jest.Mocked<TeeService>;

  beforeEach(async () => {
    const mockTeeService = {
      connectionTest: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [TeeController],
      providers: [
        {
          provide: TeeService,
          useValue: mockTeeService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<TeeController>(TeeController);
    teeService = module.get(TeeService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('connectionTest', () => {
    const dto: ConnectionTestRequestDto = {
      encryptedConfig: 'abcdef0123456789',
      epoch: 3,
    };

    it('should call teeService.connectionTest with encryptedConfig and epoch', async () => {
      const response: ConnectionTestResponseDto = {
        success: true,
        protocol: 'kubo',
        version: '0.29.0',
        latencyMs: 42,
      };
      teeService.connectionTest.mockResolvedValue(response);

      await controller.connectionTest(dto);

      expect(teeService.connectionTest).toHaveBeenCalledWith('abcdef0123456789', 3);
    });

    it('should return successful connection test response', async () => {
      const response: ConnectionTestResponseDto = {
        success: true,
        protocol: 'kubo',
        version: '0.29.0',
        latencyMs: 42,
      };
      teeService.connectionTest.mockResolvedValue(response);

      const result = await controller.connectionTest(dto);

      expect(result).toEqual(response);
    });

    it('should return failed connection test response with error', async () => {
      const response: ConnectionTestResponseDto = {
        success: false,
        latencyMs: 0,
        error: 'Connection refused',
      };
      teeService.connectionTest.mockResolvedValue(response);

      const result = await controller.connectionTest(dto);

      expect(result).toEqual(response);
      expect(result.success).toBe(false);
      expect(result.error).toBe('Connection refused');
    });

    it('should return PSA protocol response', async () => {
      const response: ConnectionTestResponseDto = {
        success: true,
        protocol: 'psa',
        latencyMs: 150,
      };
      teeService.connectionTest.mockResolvedValue(response);

      const result = await controller.connectionTest(dto);

      expect(result.protocol).toBe('psa');
    });

    it('should propagate errors from service', async () => {
      teeService.connectionTest.mockRejectedValue(new Error('TEE unavailable'));

      await expect(controller.connectionTest(dto)).rejects.toThrow('TEE unavailable');
    });
  });
});
