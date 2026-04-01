import { Test } from '@nestjs/testing';
import { HealthCheckService, TypeOrmHealthIndicator } from '@nestjs/terminus';
import { HealthController } from './health.controller';

describe('HealthController', () => {
  let controller: HealthController;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        {
          provide: HealthCheckService,
          useValue: {
            check: jest.fn().mockResolvedValue({
              status: 'ok',
              info: { database: { status: 'up' } },
              error: {},
              details: { database: { status: 'up' } },
            }),
          },
        },
        {
          provide: TypeOrmHealthIndicator,
          useValue: { pingCheck: jest.fn() },
        },
      ],
    }).compile();

    controller = module.get(HealthController);
  });

  it('should return version field matching semver pattern', async () => {
    const result = await controller.check();
    expect(result.version).toBeDefined();
    expect(result.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('should preserve existing health check fields', async () => {
    const result = await controller.check();
    expect(result.status).toBe('ok');
    expect(result.info).toEqual({ database: { status: 'up' } });
    expect(result.details).toEqual({ database: { status: 'up' } });
  });
});
