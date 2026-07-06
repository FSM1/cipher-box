/**
 * Device Registry Service
 *
 * Manages the encrypted device registry lifecycle: create for first device,
 * load existing registry, register new devices, update heartbeats, encrypt,
 * pin to IPFS, and publish via IPNS.
 *
 * Registry crypto (`deriveRegistryIpnsKeypair`/`encryptRegistry`/
 * `decryptRegistry`) and config-blob resolve/publish/transport
 * (`resolveConfigBlob`/`publishConfigBlob`/`uploadBytes`/`downloadBytes`)
 * route through the SDK facade client (D-07) instead of calling
 * `@cipherbox/core`/`sdk-core`/`ipns.service` directly. Both exported
 * functions here only run after login (the initial call site in
 * `useAuth.ts` fires after `initSdkClient`; the polling call site in
 * `useDeviceRegistrySync.ts` is gated on `isInitialized`), so `getSdkClient()`
 * is always available.
 *
 * IMPORTANT: Registry operations must NEVER block login.
 * All errors are caught and logged, returning null on failure.
 */

import type { DeviceRegistry, DeviceEntry, DevicePlatform } from '@cipherbox/core';
import { bytesToHex, hexToBytes, wrapKey, type DeviceKeypair } from '@cipherbox/crypto';
import { getSdkClient } from '../lib/sdk-provider';
import { useAuthStore } from '../stores/auth.store';
import { logger } from '../lib/logger';

/** Minimum interval between registry republishes for lastSeenAt-only changes (ms) */
const HEARTBEAT_DEBOUNCE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Initialize or sync the device registry.
 *
 * This is the main entry point called during login. It handles:
 * 1. Deriving the deterministic IPNS keypair from the user's privateKey
 * 2. Resolving an existing registry from IPNS, or creating a new one
 * 3. Adding/updating the current device in the registry
 * 4. Encrypting, pinning to IPFS, and publishing via IPNS
 * 5. Enrolling for TEE auto-republishing when teeKeys are available
 *
 * @returns Registry and IPNS name, or null if any step fails
 */
export async function initializeOrSyncRegistry(params: {
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
  deviceKeypair: DeviceKeypair;
  deviceInfo: {
    name: string;
    platform: DevicePlatform;
    appVersion: string;
    deviceModel: string;
    ipHash: string;
  };
}): Promise<{ registry: DeviceRegistry; ipnsName: string } | null> {
  try {
    const client = getSdkClient();

    // 1. Derive deterministic IPNS keypair for the registry
    const registryIpns = await client.deriveRegistryIpnsKeypair(params.userPrivateKey);

    // 2. Try to resolve existing registry
    let registry: DeviceRegistry | null = null;
    let needsPublish = true;

    const resolved = await client.resolveConfigBlob(registryIpns.ipnsName);

    if (resolved) {
      // Existing registry found -- fetch and decrypt
      const encryptedBytes = await client.downloadBytes(resolved.cid);
      registry = await client.decryptRegistry(encryptedBytes, params.userPrivateKey);

      // Snapshot before modification for change detection
      const beforeJson = JSON.stringify(registry);

      // Check if current device already exists
      const existingDevice = registry.devices.find(
        (d) => d.deviceId === params.deviceKeypair.deviceId
      );

      if (existingDevice) {
        // Update existing device heartbeat and metadata
        existingDevice.lastSeenAt = Date.now();
        existingDevice.appVersion = params.deviceInfo.appVersion;
        existingDevice.deviceModel = params.deviceInfo.deviceModel;
      } else {
        // New device -- register as pending
        const newEntry = createEmptyDeviceEntry({
          deviceKeypair: params.deviceKeypair,
          deviceInfo: params.deviceInfo,
          status: 'pending',
        });
        registry.devices.push(newEntry);
      }

      // Check if registry actually changed enough to warrant republish
      // Avoid unnecessary republishes when only lastSeenAt changed recently
      // (Pitfall 1 from RESEARCH.md: ECIES nondeterminism means every encrypt = new CID)
      const afterJson = JSON.stringify(registry);
      if (beforeJson === afterJson) {
        // Nothing changed at all
        needsPublish = false;
      } else if (existingDevice) {
        // Device existed -- check if only heartbeat fields changed
        const beforeParsed = JSON.parse(beforeJson) as DeviceRegistry;
        const beforeDevice = beforeParsed.devices.find(
          (d) => d.deviceId === params.deviceKeypair.deviceId
        );
        if (beforeDevice) {
          const metadataChanged =
            beforeDevice.appVersion !== existingDevice.appVersion ||
            beforeDevice.deviceModel !== existingDevice.deviceModel;
          if (!metadataChanged) {
            // Only lastSeenAt changed -- apply debounce
            const timeSinceLastSeen = Date.now() - beforeDevice.lastSeenAt;
            if (timeSinceLastSeen < HEARTBEAT_DEBOUNCE_MS) {
              needsPublish = false;
            }
          }
        }
      }
    } else {
      // No existing registry -- first device, auto-authorized
      registry = {
        version: 'v2',
        sequenceNumber: 0,
        devices: [
          createEmptyDeviceEntry({
            deviceKeypair: params.deviceKeypair,
            deviceInfo: params.deviceInfo,
            status: 'authorized',
          }),
        ],
      };
    }

    if (!needsPublish) {
      return { registry, ipnsName: registryIpns.ipnsName };
    }

    // 5. Increment sequence number
    registry.sequenceNumber++;

    // 6. Encrypt registry with user's public key
    const encryptedBytes = await client.encryptRegistry(registry, params.userPublicKey);

    // 7. Pin to IPFS
    const { cid } = await client.uploadBytes(encryptedBytes);

    // 8. Publish IPNS with TEE enrollment
    const teeKeys = useAuthStore.getState().teeKeys;
    let encryptedIpnsKey: string | undefined;
    let keyEpoch: number | undefined;

    if (teeKeys?.currentPublicKey) {
      // ECIES-wrap the registry IPNS private key with TEE public key
      const wrappedKey = await wrapKey(
        registryIpns.privateKey,
        hexToBytes(teeKeys.currentPublicKey)
      );
      encryptedIpnsKey = bytesToHex(wrappedKey);
      keyEpoch = teeKeys.currentEpoch;
    }

    await client.publishConfigBlob({
      ipnsPrivateKey: registryIpns.privateKey,
      ipnsName: registryIpns.ipnsName,
      metadataCid: cid,
      sequenceNumber: BigInt(registry.sequenceNumber),
      encryptedIpnsPrivateKey: encryptedIpnsKey,
      keyEpoch,
    });

    return { registry, ipnsName: registryIpns.ipnsName };
  } catch (error) {
    // Registry failures must NEVER block login
    logger.error('[DeviceRegistry] Failed to sync registry:', error);
    return null;
  }
}

/**
 * Load the registry from IPNS (read-only).
 *
 * Used by the polling hook (Plan 03) to check for remote changes.
 * Does NOT modify the registry -- just resolves, fetches, and decrypts.
 *
 * @returns Registry data with IPNS name and sequence number, or null on failure
 */
export async function loadRegistry(userPrivateKey: Uint8Array): Promise<{
  registry: DeviceRegistry;
  ipnsName: string;
  sequenceNumber: bigint;
} | null> {
  try {
    const client = getSdkClient();
    const registryIpns = await client.deriveRegistryIpnsKeypair(userPrivateKey);
    const resolved = await client.resolveConfigBlob(registryIpns.ipnsName);

    if (!resolved) {
      return null;
    }

    const encryptedBytes = await client.downloadBytes(resolved.cid);
    const registry = await client.decryptRegistry(encryptedBytes, userPrivateKey);

    return {
      registry,
      ipnsName: registryIpns.ipnsName,
      sequenceNumber: resolved.sequenceNumber,
    };
  } catch (error) {
    logger.error('[DeviceRegistry] Failed to load registry:', error);
    return null;
  }
}

/**
 * Create a new DeviceEntry with all fields populated.
 *
 * Helper that constructs a complete entry for the registry.
 *
 * @param params.deviceKeypair - Device's Ed25519 keypair with device ID
 * @param params.deviceInfo - Device metadata from detectDeviceInfo + IP hash
 * @param params.status - Authorization status ('authorized' for first device, 'pending' for subsequent)
 * @returns Complete DeviceEntry ready to add to the registry
 */
export function createEmptyDeviceEntry(params: {
  deviceKeypair: DeviceKeypair;
  deviceInfo: {
    name: string;
    platform: DevicePlatform;
    appVersion: string;
    deviceModel: string;
    ipHash: string;
  };
  status: 'authorized' | 'pending';
}): DeviceEntry {
  const now = Date.now();

  return {
    deviceId: params.deviceKeypair.deviceId,
    publicKey: bytesToHex(params.deviceKeypair.publicKey),
    name: params.deviceInfo.name,
    platform: params.deviceInfo.platform,
    appVersion: params.deviceInfo.appVersion,
    deviceModel: params.deviceInfo.deviceModel,
    ipHash: params.deviceInfo.ipHash,
    status: params.status,
    createdAt: now,
    lastSeenAt: now,
    revokedAt: null,
    revokedBy: null,
  };
}
