/**
 * SSRF Protection Utilities
 *
 * Validates user-provided endpoint URLs to prevent SSRF attacks.
 * TEE worker fetches from user-provided URLs -- must block internal/metadata endpoints.
 *
 * Extracted from migration-worker.ts for reuse across TEE routes.
 */

import { lookup } from 'node:dns/promises';

/**
 * Validate endpoint URL to prevent SSRF attacks.
 * TEE worker fetches from user-provided URLs -- must block internal/metadata endpoints.
 */
export function validateEndpointUrl(endpoint: string): void {
  const url = new URL(endpoint);

  // Skip SSRF validation in development/simulator mode
  if (process.env.TEE_MODE === 'simulator') return;

  // Must be HTTPS
  if (url.protocol !== 'https:') {
    throw new Error('Endpoint must use HTTPS');
  }

  // Block private/internal IP ranges and metadata endpoints
  const hostname = url.hostname;
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    hostname === '169.254.169.254' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local') ||
    hostname.startsWith('169.254.') ||
    hostname.startsWith('fd') ||
    hostname.startsWith('fe80')
  ) {
    throw new Error('Endpoint cannot target private/internal addresses');
  }

  // Block 172.16.0.0/12 range
  if (hostname.startsWith('172.')) {
    const second = parseInt(hostname.split('.')[1], 10);
    if (second >= 16 && second <= 31) {
      throw new Error('Endpoint cannot target private/internal addresses');
    }
  }
}

/**
 * DNS rebinding protection: resolve hostname and verify IP is not private.
 * Prevents attacker.com -> 169.254.169.254 attacks.
 */
export async function validateResolvedIp(hostname: string): Promise<void> {
  const result = await lookup(hostname);
  const ip = result.address;
  if (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip === '::1' ||
    ip.startsWith('169.254.') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80')
  ) {
    throw new Error('Endpoint DNS resolves to private address');
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) {
      throw new Error('Endpoint DNS resolves to private address');
    }
  }
}
