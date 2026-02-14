/**
 * Device Identity Persistence
 *
 * Manages the device's Ed25519 keypair in IndexedDB. This keypair is unique
 * per physical device/browser and cannot be re-derived (unlike the user's
 * vault key which comes from Web3Auth).
 *
 * If IndexedDB is unavailable (incognito, etc.) or the stored keypair is
 * cleared by the browser, a new keypair is generated. This creates a new
 * device entry in the registry (the old one becomes orphaned).
 */

import { generateDeviceKeypair, deriveDeviceId, type DeviceKeypair } from '@cipherbox/crypto';

const DB_NAME = 'cipherbox-device';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const KEYPAIR_KEY = 'device-ed25519';

/**
 * Open the IndexedDB database, creating the object store on upgrade.
 */
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Load device keypair from IndexedDB.
 *
 * Stores keys as plain number arrays because Uint8Array doesn't
 * serialize reliably across all browsers in IndexedDB.
 *
 * @returns Keypair if found, null if not found or IndexedDB unavailable
 */
async function loadDeviceKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} | null> {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.get(KEYPAIR_KEY);
      request.onsuccess = () => {
        const val = request.result;
        if (val && val.publicKey && val.privateKey) {
          resolve({
            publicKey: new Uint8Array(val.publicKey),
            privateKey: new Uint8Array(val.privateKey),
          });
        } else {
          resolve(null);
        }
      };
      request.onerror = () => reject(request.error);
    });
  } catch {
    // IndexedDB unavailable (incognito, etc.)
    return null;
  }
}

/**
 * Save device keypair to IndexedDB.
 *
 * Converts Uint8Array to plain number arrays before storing
 * to avoid serialization issues across browsers.
 */
async function saveDeviceKeypair(keypair: {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);

  store.put(
    {
      publicKey: Array.from(keypair.publicKey),
      privateKey: Array.from(keypair.privateKey),
    },
    KEYPAIR_KEY
  );

  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Get or create the device's Ed25519 identity.
 *
 * Tries to load an existing keypair from IndexedDB first.
 * If not found, generates a new one and persists it.
 *
 * The returned DeviceKeypair includes:
 * - publicKey: 32-byte Ed25519 public key
 * - privateKey: 32-byte Ed25519 private key (seed)
 * - deviceId: SHA-256 hex of the public key
 *
 * @returns Device keypair with derived device ID
 */
export async function getOrCreateDeviceIdentity(): Promise<DeviceKeypair> {
  // Try loading existing keypair from IndexedDB
  const stored = await loadDeviceKeypair();
  if (stored) {
    const deviceId = deriveDeviceId(stored.publicKey);
    return {
      publicKey: stored.publicKey,
      privateKey: stored.privateKey,
      deviceId,
    };
  }

  // Generate new keypair and persist
  const keypair = generateDeviceKeypair();
  await saveDeviceKeypair({
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
  });

  return keypair;
}
