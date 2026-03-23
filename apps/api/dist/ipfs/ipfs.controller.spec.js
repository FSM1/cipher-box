"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const testing_1 = require("@nestjs/testing");
const common_1 = require("@nestjs/common");
const ipfs_controller_1 = require("./ipfs.controller");
const providers_1 = require("./providers");
const jwt_auth_guard_1 = require("../auth/guards/jwt-auth.guard");
const vault_service_1 = require("../vault/vault.service");
describe('IpfsController', () => {
    let controller;
    let ipfsProvider;
    let vaultService;
    beforeEach(async () => {
        const mockIpfsProvider = {
            pinFile: jest.fn(),
            unpinFile: jest.fn(),
            getFile: jest.fn(),
        };
        const mockVaultService = {
            checkQuota: jest.fn(),
            recordPin: jest.fn(),
        };
        const module = await testing_1.Test.createTestingModule({
            controllers: [ipfs_controller_1.IpfsController],
            providers: [
                {
                    provide: providers_1.IPFS_PROVIDER,
                    useValue: mockIpfsProvider,
                },
                {
                    provide: vault_service_1.VaultService,
                    useValue: mockVaultService,
                },
            ],
        })
            .overrideGuard(jwt_auth_guard_1.JwtAuthGuard)
            .useValue({ canActivate: () => true })
            .compile();
        controller = module.get(ipfs_controller_1.IpfsController);
        ipfsProvider = module.get(providers_1.IPFS_PROVIDER);
        vaultService = module.get(vault_service_1.VaultService);
    });
    afterEach(() => {
        jest.resetAllMocks();
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
        const mockReq = { user: { id: 'user-123' } };
        it('should check quota, pin file, record pin, and return result', async () => {
            const mockFile = {
                buffer: Buffer.from('encrypted file content'),
                size: 22,
            };
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
            };
            vaultService.checkQuota.mockResolvedValue(false);
            await expect(controller.upload(mockReq, mockFile)).rejects.toThrow(common_1.PayloadTooLargeException);
            expect(ipfsProvider.pinFile).not.toHaveBeenCalled();
            expect(vaultService.recordPin).not.toHaveBeenCalled();
        });
        it('should unpin file if recordPin fails', async () => {
            const mockFile = {
                buffer: Buffer.from('encrypted file content'),
                size: 22,
            };
            vaultService.checkQuota.mockResolvedValue(true);
            ipfsProvider.pinFile.mockResolvedValue({ cid: mockCid, size: mockSize });
            vaultService.recordPin.mockRejectedValue(new Error('DB error'));
            ipfsProvider.unpinFile.mockResolvedValue(undefined);
            await expect(controller.upload(mockReq, mockFile)).rejects.toThrow('DB error');
            expect(ipfsProvider.unpinFile).toHaveBeenCalledWith(mockCid);
        });
        it('should not record pin if pinFile fails', async () => {
            const mockFile = {
                buffer: Buffer.from('encrypted file content'),
                size: 22,
            };
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
            };
            ipfsProvider.getFile.mockResolvedValue(mockContent);
            await controller.get(mockCid, mockRes);
            expect(ipfsProvider.getFile).toHaveBeenCalledWith(mockCid);
        });
        it('should set correct response headers', async () => {
            const mockRes = {
                set: jest.fn(),
            };
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
            };
            ipfsProvider.getFile.mockResolvedValue(mockContent);
            const result = await controller.get(mockCid, mockRes);
            expect(result).toBeInstanceOf((await Promise.resolve().then(() => __importStar(require('@nestjs/common')))).StreamableFile);
        });
        it('should call provider exactly once', async () => {
            const mockRes = {
                set: jest.fn(),
            };
            ipfsProvider.getFile.mockResolvedValue(mockContent);
            await controller.get(mockCid, mockRes);
            expect(ipfsProvider.getFile).toHaveBeenCalledTimes(1);
        });
    });
});
//# sourceMappingURL=ipfs.controller.spec.js.map