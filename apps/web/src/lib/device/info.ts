/**
 * Device Info Detection
 *
 * Auto-detects device metadata from the browser environment.
 * Used to populate the device entry when registering in the
 * encrypted device registry.
 */

import { bytesToHex, CRYPTO_VERSION, type DevicePlatform } from '@cipherbox/crypto';

/**
 * Auto-detect device information from the browser environment.
 *
 * Returns platform-appropriate metadata for the device registry entry.
 * Device name and model are kept simple -- users can rename in Settings.
 *
 * @returns Device metadata for registry registration
 */
export function detectDeviceInfo(): {
  name: string;
  platform: DevicePlatform;
  appVersion: string;
  deviceModel: string;
} {
  const ua = navigator.userAgent;

  // Detect platform
  const platform = detectPlatform(ua);

  // Detect browser name
  const browserName = detectBrowser(ua);

  // Detect OS name + version
  const osInfo = detectOS(ua);

  // Device name: "Chrome on macOS" style
  const name = `${browserName} on ${osInfo.name}`;

  // Device model: "Chrome 123 on macOS 15.2" style
  const deviceModel = `${browserName} on ${osInfo.name}${osInfo.version ? ` ${osInfo.version}` : ''}`;

  // App version: prefer VITE_APP_VERSION env var, fall back to CRYPTO_VERSION
  const appVersion = import.meta.env.VITE_APP_VERSION || CRYPTO_VERSION;

  return { name, platform, appVersion, deviceModel };
}

/**
 * Detect the platform from the user agent string.
 */
function detectPlatform(ua: string): DevicePlatform {
  if (/Macintosh|Mac OS X/i.test(ua)) return 'macos';
  if (/Windows/i.test(ua)) return 'windows';
  if (/Linux/i.test(ua)) return 'linux';
  return 'web';
}

/**
 * Detect the browser name from the user agent string.
 */
function detectBrowser(ua: string): string {
  // Order matters -- check more specific browsers first
  if (/Edg\//i.test(ua)) return 'Edge';
  if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return 'Opera';
  if (/Firefox\//i.test(ua)) return 'Firefox';
  if (/Chrome\//i.test(ua)) return 'Chrome';
  if (/Safari\//i.test(ua)) return 'Safari';
  return 'Browser';
}

/**
 * Detect OS name and version from the user agent string.
 */
function detectOS(ua: string): { name: string; version: string } {
  // macOS
  const macMatch = ua.match(/Mac OS X (\d+[._]\d+(?:[._]\d+)?)/);
  if (macMatch) {
    return { name: 'macOS', version: macMatch[1].replace(/_/g, '.') };
  }

  // Windows
  const winMatch = ua.match(/Windows NT (\d+\.\d+)/);
  if (winMatch) {
    const ntVersionMap: Record<string, string> = {
      '10.0': '10/11',
      '6.3': '8.1',
      '6.2': '8',
      '6.1': '7',
    };
    const friendlyVersion = ntVersionMap[winMatch[1]] || winMatch[1];
    return { name: 'Windows', version: friendlyVersion };
  }

  // Linux
  if (/Linux/i.test(ua)) {
    return { name: 'Linux', version: '' };
  }

  return { name: 'Unknown OS', version: '' };
}

/**
 * Compute a privacy-preserving hash of an IP address.
 *
 * The actual IP is obtained from the backend; this function
 * hashes it locally before storing in the registry.
 *
 * Uses Web Crypto SHA-256 (available in all modern browsers).
 *
 * @param ipAddress - IP address string (e.g., "192.168.1.1")
 * @returns Hex-encoded SHA-256 hash
 */
export async function computeIpHash(ipAddress: string): Promise<string> {
  const data = new TextEncoder().encode(ipAddress);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hashBuffer));
}
