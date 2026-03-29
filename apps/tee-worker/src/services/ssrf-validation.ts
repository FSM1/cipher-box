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
 * Check if an address (hostname or resolved IP) is in a private/internal range.
 *
 * Covers: RFC 1918, loopback, link-local, CGN (RFC 6598), unique-local IPv6,
 * IPv4-mapped IPv6, metadata endpoints, and .internal/.local suffixes.
 */
function isPrivateAddress(addr: string): boolean {
  // Strip IPv6 brackets from URL.hostname (e.g. [::1] → ::1)
  const stripped = addr.startsWith('[') && addr.endsWith(']') ? addr.slice(1, -1) : addr;
  // Strip IPv4-mapped IPv6 prefix (::ffff:127.0.0.1 → 127.0.0.1)
  const normalized = stripped.startsWith('::ffff:') ? stripped.slice(7) : stripped;

  return (
    normalized === 'localhost' ||
    normalized === '0.0.0.0' ||
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('10.') ||
    normalized.startsWith('192.168.') ||
    normalized.startsWith('127.') ||
    normalized.startsWith('169.254.') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fe80') ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.local') ||
    is172Private(normalized) ||
    isCgnRange(normalized)
  );
}

/** RFC 1918: 172.16.0.0/12 */
function is172Private(addr: string): boolean {
  if (!addr.startsWith('172.')) return false;
  const second = parseInt(addr.split('.')[1], 10);
  return second >= 16 && second <= 31;
}

/** RFC 6598: Carrier-Grade NAT 100.64.0.0/10 */
function isCgnRange(addr: string): boolean {
  if (!addr.startsWith('100.')) return false;
  const second = parseInt(addr.split('.')[1], 10);
  return second >= 64 && second <= 127;
}

/**
 * Validate endpoint URL to prevent SSRF attacks.
 * TEE worker fetches from user-provided URLs -- must block internal/metadata endpoints.
 */
export function validateEndpointUrl(endpoint: string): void {
  const url = new URL(endpoint);

  if (process.env.TEE_MODE === 'simulator') return;

  if (url.protocol !== 'https:') {
    throw new Error('Endpoint must use HTTPS');
  }

  if (isPrivateAddress(url.hostname)) {
    throw new Error('Endpoint cannot target private/internal addresses');
  }
}

/**
 * DNS rebinding protection: resolve hostname and verify IP is not private.
 * Prevents attacker.com -> 169.254.169.254 attacks.
 */
export async function validateResolvedIp(hostname: string): Promise<void> {
  const result = await lookup(hostname);
  if (isPrivateAddress(result.address)) {
    throw new Error('Endpoint DNS resolves to private address');
  }
}

/**
 * Shared fetch wrapper that disables redirects to prevent SSRF via redirect.
 * An attacker's server could 302 to http://169.254.169.254/... after passing
 * the initial URL validation.
 */
export async function ssrfSafeFetch(url: string, init?: RequestInit): Promise<Response> {
  return fetch(url, { ...init, redirect: 'error' });
}
