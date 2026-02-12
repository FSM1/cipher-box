"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const testing_1 = require("@nestjs/testing");
const common_1 = require("@nestjs/common");
const vault_controller_1 = require("./vault.controller");
const vault_service_1 = require("./vault.service");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
describe('VaultController', () => {
    let controller;
    let vaultService;
    const mockUser = {
        id: 'user-uuid-123',
    };
    const mockVaultResponse = {
        id: 'vault-uuid-123',
        ownerPublicKey: '04abcd1234567890',
        encryptedRootFolderKey: 'encrypted-folder-key-hex',
        encryptedRootIpnsPrivateKey: 'encrypted-ipns-key-hex',
        rootIpnsName: 'k51qzi5uqu5test',
        rootIpnsPublicKey: 'd'.repeat(64), // 32-byte Ed25519 public key
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
        const module = await testing_1.Test.createTestingModule({
            controllers: [vault_controller_1.VaultController],
            providers: [
                {
                    provide: vault_service_1.VaultService,
                    useValue: mockVaultService,
                },
            ],
        })
            .overrideGuard(jwt_auth_guard_1.JwtAuthGuard)
            .useValue({ canActivate: () => true })
            .compile();
        controller = module.get(vault_controller_1.VaultController);
        vaultService = module.get(vault_service_1.VaultService);
    });
    afterEach(() => {
        jest.resetAllMocks();
    });
    describe('initializeVault', () => {
        const initVaultDto = {
            ownerPublicKey: '04abcd1234567890',
            encryptedRootFolderKey: 'encrypted-folder-key-hex',
            encryptedRootIpnsPrivateKey: 'encrypted-ipns-key-hex',
            rootIpnsName: 'k51qzi5uqu5test',
            rootIpnsPublicKey: 'd'.repeat(64), // 32-byte Ed25519 public key
        };
        it('should call vaultService.initializeVault with user.id and dto', async () => {
            const mockRequest = {
                user: mockUser,
            };
            vaultService.initializeVault.mockResolvedValue(mockVaultResponse);
            await controller.initializeVault(mockRequest, initVaultDto);
            expect(vaultService.initializeVault).toHaveBeenCalledWith('user-uuid-123', initVaultDto);
        });
        it('should return vault response', async () => {
            const mockRequest = {
                user: mockUser,
            };
            vaultService.initializeVault.mockResolvedValue(mockVaultResponse);
            const result = await controller.initializeVault(mockRequest, initVaultDto);
            expect(result).toEqual(mockVaultResponse);
        });
    });
    describe('getVault', () => {
        it('should call vaultService.findVault with user.id', async () => {
            const mockRequest = {
                user: mockUser,
            };
            vaultService.findVault.mockResolvedValue(mockVaultResponse);
            await controller.getVault(mockRequest);
            expect(vaultService.findVault).toHaveBeenCalledWith('user-uuid-123');
        });
        it('should throw NotFoundException if vault is null', async () => {
            const mockRequest = {
                user: mockUser,
            };
            vaultService.findVault.mockResolvedValue(null);
            await expect(controller.getVault(mockRequest)).rejects.toThrow(common_1.NotFoundException);
            await expect(controller.getVault(mockRequest)).rejects.toThrow('Vault not found');
        });
        it('should return vault response if found', async () => {
            const mockRequest = {
                user: mockUser,
            };
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
            };
            vaultService.getQuota.mockResolvedValue(mockQuotaResponse);
            await controller.getQuota(mockRequest);
            expect(vaultService.getQuota).toHaveBeenCalledWith('user-uuid-123');
        });
        it('should return quota response', async () => {
            const mockRequest = {
                user: mockUser,
            };
            vaultService.getQuota.mockResolvedValue(mockQuotaResponse);
            const result = await controller.getQuota(mockRequest);
            expect(result).toEqual(mockQuotaResponse);
        });
    });
});
//# sourceMappingURL=vault.controller.spec.js.map