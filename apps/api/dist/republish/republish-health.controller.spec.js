"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const testing_1 = require("@nestjs/testing");
const republish_health_controller_1 = require("./republish-health.controller");
const republish_service_1 = require("./republish.service");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
describe('RepublishHealthController', () => {
    let controller;
    let republishService;
    beforeEach(async () => {
        const mockRepublishService = {
            getHealthStats: jest.fn(),
        };
        const module = await testing_1.Test.createTestingModule({
            controllers: [republish_health_controller_1.RepublishHealthController],
            providers: [{ provide: republish_service_1.RepublishService, useValue: mockRepublishService }],
        })
            .overrideGuard(jwt_auth_guard_1.JwtAuthGuard)
            .useValue({ canActivate: () => true })
            .compile();
        controller = module.get(republish_health_controller_1.RepublishHealthController);
        republishService = module.get(republish_service_1.RepublishService);
    });
    afterEach(() => {
        jest.clearAllMocks();
    });
    describe('getHealth', () => {
        it('should return health stats from the service', async () => {
            const lastRunDate = new Date('2026-01-15T12:00:00Z');
            republishService.getHealthStats.mockResolvedValue({
                pending: 42,
                failed: 3,
                stale: 1,
                lastRunAt: lastRunDate,
                currentEpoch: 5,
                teeHealthy: true,
            });
            const result = await controller.getHealth();
            expect(result).toEqual({
                pending: 42,
                failed: 3,
                stale: 1,
                lastRunAt: lastRunDate,
                currentEpoch: 5,
                teeHealthy: true,
            });
            expect(republishService.getHealthStats).toHaveBeenCalledTimes(1);
        });
        it('should return null lastRunAt when no republish has ever run', async () => {
            republishService.getHealthStats.mockResolvedValue({
                pending: 0,
                failed: 0,
                stale: 0,
                lastRunAt: null,
                currentEpoch: null,
                teeHealthy: false,
            });
            const result = await controller.getHealth();
            expect(result).toEqual({
                pending: 0,
                failed: 0,
                stale: 0,
                lastRunAt: null,
                currentEpoch: null,
                teeHealthy: false,
            });
        });
        it('should return teeHealthy=false when TEE is unreachable', async () => {
            republishService.getHealthStats.mockResolvedValue({
                pending: 10,
                failed: 5,
                stale: 2,
                lastRunAt: new Date('2026-01-10'),
                currentEpoch: 3,
                teeHealthy: false,
            });
            const result = await controller.getHealth();
            expect(result.teeHealthy).toBe(false);
            expect(result.pending).toBe(10);
            expect(result.currentEpoch).toBe(3);
        });
        it('should return all zero counts when system is fresh', async () => {
            republishService.getHealthStats.mockResolvedValue({
                pending: 0,
                failed: 0,
                stale: 0,
                lastRunAt: null,
                currentEpoch: 1,
                teeHealthy: true,
            });
            const result = await controller.getHealth();
            expect(result.pending).toBe(0);
            expect(result.failed).toBe(0);
            expect(result.stale).toBe(0);
            expect(result.lastRunAt).toBeNull();
            expect(result.currentEpoch).toBe(1);
            expect(result.teeHealthy).toBe(true);
        });
        it('should propagate errors from the service', async () => {
            republishService.getHealthStats.mockRejectedValue(new Error('Database connection failed'));
            await expect(controller.getHealth()).rejects.toThrow('Database connection failed');
        });
    });
});
//# sourceMappingURL=republish-health.controller.spec.js.map