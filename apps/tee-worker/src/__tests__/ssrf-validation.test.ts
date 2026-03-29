/**
 * SSRF Validation Tests
 *
 * Tests for the SSRF protection utilities used by TEE worker routes.
 * Covers private IP ranges, DNS rebinding prevention, redirect blocking,
 * and edge cases from security review REVIEW-2026-03-25-phase-21.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  validateEndpointUrl,
  validateResolvedIp,
  ssrfSafeFetch,
} from '../services/ssrf-validation.js';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

describe('ssrf-validation', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'production';
  });

  describe('validateEndpointUrl', () => {
    it('accepts valid HTTPS URLs', () => {
      expect(() => validateEndpointUrl('https://api.pinata.cloud')).not.toThrow();
      expect(() => validateEndpointUrl('https://ipfs.example.com:5001')).not.toThrow();
    });

    it('rejects HTTP URLs', () => {
      expect(() => validateEndpointUrl('http://api.pinata.cloud')).toThrow('HTTPS');
    });

    // RFC 1918: 10.0.0.0/8
    it('rejects 10.x.x.x private range', () => {
      expect(() => validateEndpointUrl('https://10.0.0.1')).toThrow('private');
      expect(() => validateEndpointUrl('https://10.255.255.255')).toThrow('private');
    });

    // RFC 1918: 192.168.0.0/16
    it('rejects 192.168.x.x private range', () => {
      expect(() => validateEndpointUrl('https://192.168.1.1')).toThrow('private');
      expect(() => validateEndpointUrl('https://192.168.0.1')).toThrow('private');
    });

    // RFC 1918: 172.16.0.0/12
    it('rejects 172.16-31.x.x private range', () => {
      expect(() => validateEndpointUrl('https://172.16.0.1')).toThrow('private');
      expect(() => validateEndpointUrl('https://172.31.255.255')).toThrow('private');
    });

    it('accepts 172.15.x.x and 172.32.x.x (outside /12)', () => {
      expect(() => validateEndpointUrl('https://172.15.0.1')).not.toThrow();
      expect(() => validateEndpointUrl('https://172.32.0.1')).not.toThrow();
    });

    // Loopback
    it('rejects localhost and 127.x.x.x', () => {
      expect(() => validateEndpointUrl('https://localhost')).toThrow('private');
      expect(() => validateEndpointUrl('https://127.0.0.1')).toThrow('private');
      expect(() => validateEndpointUrl('https://127.0.0.2')).toThrow('private');
    });

    // Link-local
    it('rejects 169.254.x.x link-local (AWS metadata)', () => {
      expect(() => validateEndpointUrl('https://169.254.169.254')).toThrow('private');
      expect(() => validateEndpointUrl('https://169.254.0.1')).toThrow('private');
    });

    // IPv6
    it('rejects IPv6 loopback and link-local', () => {
      expect(() => validateEndpointUrl('https://[::1]')).toThrow('private');
      expect(() => validateEndpointUrl('https://[fe80::1]')).toThrow('private');
    });

    // Unique-local IPv6
    it('rejects fd00::/8 and fc00::/7 unique-local IPv6', () => {
      expect(() => validateEndpointUrl('https://[fd00::1]')).toThrow('private');
      expect(() => validateEndpointUrl('https://[fc00::1]')).toThrow('private');
    });

    // 0.0.0.0
    it('rejects 0.0.0.0', () => {
      expect(() => validateEndpointUrl('https://0.0.0.0')).toThrow('private');
    });

    // RFC 6598: CGN range 100.64.0.0/10
    it('rejects CGN range 100.64-127.x.x', () => {
      expect(() => validateEndpointUrl('https://100.64.0.1')).toThrow('private');
      expect(() => validateEndpointUrl('https://100.127.255.255')).toThrow('private');
    });

    it('accepts 100.63.x.x and 100.128.x.x (outside CGN)', () => {
      expect(() => validateEndpointUrl('https://100.63.0.1')).not.toThrow();
      expect(() => validateEndpointUrl('https://100.128.0.1')).not.toThrow();
    });

    // Internal/local suffixes
    it('rejects .internal and .local suffixes', () => {
      expect(() => validateEndpointUrl('https://metadata.internal')).toThrow('private');
      expect(() => validateEndpointUrl('https://ipfs.local')).toThrow('private');
    });

    // Simulator mode bypasses
    it('skips validation in simulator mode', () => {
      process.env.TEE_MODE = 'simulator';
      expect(() => validateEndpointUrl('http://localhost:5001')).not.toThrow();
    });
  });

  describe('validateResolvedIp', () => {
    it('rejects hostname resolving to private IP', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '169.254.169.254', family: 4 });

      await expect(validateResolvedIp('evil.attacker.com')).rejects.toThrow('private');
    });

    it('rejects IPv4-mapped IPv6 private address', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '::ffff:127.0.0.1', family: 6 });

      await expect(validateResolvedIp('evil.attacker.com')).rejects.toThrow('private');
    });

    it('accepts hostname resolving to public IP', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 });

      await expect(validateResolvedIp('example.com')).resolves.toBeUndefined();
    });
  });

  describe('ssrfSafeFetch', () => {
    it('pins DNS and sets redirect to error in CVM mode', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 });

      const mockFetch = vi.fn().mockResolvedValue(new Response('ok'));
      vi.stubGlobal('fetch', mockFetch);

      await ssrfSafeFetch('https://example.com/test', { method: 'GET' });

      // URL should have pinned IP, with Host header for TLS SNI
      expect(mockFetch).toHaveBeenCalledWith('https://93.184.216.34/test', {
        method: 'GET',
        redirect: 'error',
        headers: { host: 'example.com' },
      });
    });

    it('rejects DNS resolving to private IP', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '169.254.169.254', family: 4 });

      await expect(ssrfSafeFetch('https://evil.com/test')).rejects.toThrow('private');
    });

    it('skips DNS pinning in simulator mode', async () => {
      process.env.TEE_MODE = 'simulator';
      const mockFetch = vi.fn().mockResolvedValue(new Response('ok'));
      vi.stubGlobal('fetch', mockFetch);

      await ssrfSafeFetch('https://example.com/test', { method: 'GET' });

      // In simulator mode, URL is passed through unchanged
      expect(mockFetch).toHaveBeenCalledWith('https://example.com/test', {
        method: 'GET',
        redirect: 'error',
      });
    });

    it('preserves request options and adds Host header in CVM mode', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.lookup).mockResolvedValue({ address: '93.184.216.34', family: 4 });

      const mockFetch = vi.fn().mockResolvedValue(new Response('ok'));
      vi.stubGlobal('fetch', mockFetch);

      await ssrfSafeFetch('https://example.com', {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
      });

      const callArgs = mockFetch.mock.calls[0][1];
      expect(callArgs.method).toBe('POST');
      expect(callArgs.headers).toHaveProperty('authorization', 'Bearer token');
      expect(callArgs.headers).toHaveProperty('host', 'example.com');
      expect(callArgs.redirect).toBe('error');
    });
  });

  describe('migrate route batch size limit', () => {
    // Integration-level test suggestion: verify /migrate rejects > 50 CIDs
    it.todo('rejects batch sizes exceeding MAX_BATCH_SIZE (50)');
    it.todo('accepts batch sizes within limit');
  });

  describe('credential zeroing', () => {
    it.todo('TEE private key is zeroed after ECIES decryption');
    it.todo('auth token bytes are zeroed in finally block after migration batch');
    it.todo('config bytes are zeroed in finally block after connection test');
  });

  describe('ECIES credential flow', () => {
    it.todo('connection test rejects malformed hex in encryptedConfig');
    it.todo('connection test rejects missing epoch parameter');
    it.todo('migration rejects ECIES decryption with wrong epoch key');
  });
});
