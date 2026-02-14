/**
 * @cipherbox/crypto - Device Registry Types
 *
 * Type definitions for the encrypted device registry stored on IPFS/IPNS.
 * The registry tracks authenticated devices with rich metadata and supports
 * cross-device approval (Phase 12.4).
 */

/** Authorization status for a device in the registry */
export type DeviceAuthStatus = 'pending' | 'authorized' | 'revoked';

/** Platform identifier for a device */
export type DevicePlatform = 'web' | 'macos' | 'linux' | 'windows';

/**
 * Individual device entry in the registry.
 *
 * Each entry represents a physical device that has authenticated
 * with the user's CipherBox account.
 */
export type DeviceEntry = {
  /** SHA-256 hash of device's Ed25519 public key (hex) */
  deviceId: string;
  /** Device's Ed25519 public key (hex) - for future key exchange in Phase 12.4 */
  publicKey: string;
  /** Human-readable device name (e.g., "Chrome on macOS") */
  name: string;
  /** Platform identifier */
  platform: DevicePlatform;
  /** App version string (e.g., "0.2.0") */
  appVersion: string;
  /** Device model or OS version (e.g., "macOS 15.2", "Chrome 123") */
  deviceModel: string;
  /** SHA-256 hash of IP address at registration (hex, privacy-preserving) */
  ipHash: string;
  /** Authorization status */
  status: DeviceAuthStatus;
  /** When device was first registered (Unix ms) */
  createdAt: number;
  /** Last time device synced with registry (Unix ms) */
  lastSeenAt: number;
  /** When device was revoked (Unix ms, null if not revoked) */
  revokedAt: number | null;
  /** Device ID of the device that performed revocation (null if not revoked) */
  revokedBy: string | null;
};

/**
 * The full device registry.
 *
 * Encrypted as a single JSON blob with the user's publicKey via ECIES,
 * then stored on IPFS and referenced by a dedicated IPNS name.
 */
export type DeviceRegistry = {
  /** Schema version for future migrations */
  version: 'v1';
  /** Monotonically increasing update counter */
  sequenceNumber: number;
  /** Array of all device entries (including revoked, for audit trail) */
  devices: DeviceEntry[];
};
