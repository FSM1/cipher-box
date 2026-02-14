import { UnauthorizedException } from '@nestjs/common';
import { SiweService } from './siwe.service';

// Mock viem modules
jest.mock('viem', () => ({
  getAddress: jest.fn((addr: string) => {
    // Simple mock: return mixed-case checksummed format
    if (addr.toLowerCase() === '0xd8da6bf26964af9d7eed9e03e53415d37aa96045') {
      return '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    }
    return addr;
  }),
  verifyMessage: jest.fn(),
}));

jest.mock('viem/siwe', () => ({
  parseSiweMessage: jest.fn(),
  validateSiweMessage: jest.fn(),
}));

import { getAddress, verifyMessage } from 'viem';
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe';

const mockGetAddress = getAddress as jest.Mock;
const mockParseSiweMessage = parseSiweMessage as jest.Mock;
const mockValidateSiweMessage = validateSiweMessage as jest.Mock;
const mockVerifyMessage = verifyMessage as jest.Mock;

describe('SiweService', () => {
  let service: SiweService;

  beforeEach(() => {
    service = new SiweService();
    jest.clearAllMocks();
  });

  describe('generateNonce', () => {
    it('should return a 32 hex character nonce', () => {
      const nonce = service.generateNonce();
      expect(nonce).toMatch(/^[0-9a-f]{32}$/);
    });

    it('should generate unique nonces', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 100; i++) {
        nonces.add(service.generateNonce());
      }
      expect(nonces.size).toBe(100);
    });
  });

  describe('hashWalletAddress', () => {
    it('should produce consistent SHA-256 hash for the same address regardless of case', () => {
      const lowercaseAddr = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045';
      const checksummedAddr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

      // getAddress always returns the same checksummed form
      mockGetAddress.mockReturnValue(checksummedAddr);

      const hash1 = service.hashWalletAddress(lowercaseAddr);
      const hash2 = service.hashWalletAddress(checksummedAddr);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
      expect(mockGetAddress).toHaveBeenCalledTimes(2);
    });
  });

  describe('hashIdentifier', () => {
    it('should return consistent SHA-256 hex for a known input', () => {
      const hash = service.hashIdentifier('test@example.com');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      // Same input should always produce the same hash
      const hash2 = service.hashIdentifier('test@example.com');
      expect(hash).toBe(hash2);
    });

    it('should NOT normalize input (caller must normalize)', () => {
      const hash1 = service.hashIdentifier('Test@Example.com');
      const hash2 = service.hashIdentifier('test@example.com');
      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = service.hashIdentifier('user1@example.com');
      const hash2 = service.hashIdentifier('user2@example.com');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('truncateWalletAddress', () => {
    it('should truncate to first 6 + "..." + last 4 chars', () => {
      const addr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
      mockGetAddress.mockReturnValue(addr);

      const result = service.truncateWalletAddress(addr);

      expect(result).toBe('0xd8dA...6045');
    });

    it('should normalize address before truncating', () => {
      const lowercaseAddr = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045';
      const checksummedAddr = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
      mockGetAddress.mockReturnValue(checksummedAddr);

      const result = service.truncateWalletAddress(lowercaseAddr);

      expect(result).toBe('0xd8dA...6045');
      expect(mockGetAddress).toHaveBeenCalledWith(lowercaseAddr);
    });
  });

  describe('truncateEmail', () => {
    it('should truncate long local part: first 3 + "..." + last 2 + domain', () => {
      expect(service.truncateEmail('michael@gmail.com')).toBe('mic...el@gmail.com');
    });

    it('should not truncate short local parts (≤5 chars)', () => {
      expect(service.truncateEmail('bob@x.com')).toBe('bob@x.com');
      expect(service.truncateEmail('alice@example.com')).toBe('alice@example.com');
      expect(service.truncateEmail('jo@a.co')).toBe('jo@a.co');
    });

    it('should truncate exactly 6-char local part', () => {
      expect(service.truncateEmail('abcdef@test.com')).toBe('abc...ef@test.com');
    });

    it('should return as-is if no @ symbol', () => {
      expect(service.truncateEmail('noemail')).toBe('noemail');
    });
  });

  describe('verifySiweMessage', () => {
    const testMessage = 'example.com wants you to sign in with your Ethereum account...';
    const testSignature = '0xabc123' as `0x${string}`;
    const testNonce = 'abc123def456abc123def456abc123de';
    const testDomain = 'example.com';
    const testAddress = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

    it('should return checksummed address on valid verification', async () => {
      mockParseSiweMessage.mockReturnValue({ address: testAddress, nonce: testNonce });
      mockValidateSiweMessage.mockReturnValue(true);
      mockVerifyMessage.mockResolvedValue(true);
      mockGetAddress.mockReturnValue(testAddress);

      const result = await service.verifySiweMessage(
        testMessage,
        testSignature,
        testNonce,
        testDomain
      );

      expect(result).toBe(testAddress);
      expect(mockParseSiweMessage).toHaveBeenCalledWith(testMessage);
      expect(mockValidateSiweMessage).toHaveBeenCalledWith({
        message: { address: testAddress, nonce: testNonce },
        domain: testDomain,
        nonce: testNonce,
      });
      expect(mockVerifyMessage).toHaveBeenCalledWith({
        address: testAddress,
        message: testMessage,
        signature: testSignature,
      });
    });

    it('should throw UnauthorizedException if message has no address', async () => {
      mockParseSiweMessage.mockReturnValue({ nonce: testNonce });

      await expect(
        service.verifySiweMessage(testMessage, testSignature, testNonce, testDomain)
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if message validation fails', async () => {
      mockParseSiweMessage.mockReturnValue({ address: testAddress, nonce: testNonce });
      mockValidateSiweMessage.mockReturnValue(false);

      await expect(
        service.verifySiweMessage(testMessage, testSignature, testNonce, testDomain)
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if signature is invalid', async () => {
      mockParseSiweMessage.mockReturnValue({ address: testAddress, nonce: testNonce });
      mockValidateSiweMessage.mockReturnValue(true);
      mockVerifyMessage.mockResolvedValue(false);

      await expect(
        service.verifySiweMessage(testMessage, testSignature, testNonce, testDomain)
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
