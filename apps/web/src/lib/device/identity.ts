/**
 * Device Identity Persistence
 *
 * Manages the device's Ed25519 keypair in IndexedDB. This keypair is unique
 * per physical device/browser and cannot be re-derived (unlike the user's
 * vault key which comes from Web3Auth).
 *
 * [H-08] The device private key is encrypted at rest using AES-256-GCM with
 * a key derived via HKDF from the user's vault private key. This prevents
 * extraction of the device private key if IndexedDB is compromised.
 *
 * If IndexedDB is unavailable (incognito, etc.) or the stored keypair is
 * cleared by the browser, a new keypair is generated. This creates a new
 * device entry in the registry (the old one becomes orphaned).
 *
 * Migration: Old v1 (plaintext) entries lack a `version` field. When
 * `loadDeviceKeypair` encounters a v1 entry, it returns null, triggering
 * new keypair generation. The old device entry becomes orphaned (acceptable
 * per existing design doc).
 */

import { generateDeviceKeypair, deriveDeviceId, type DeviceKeypair } from '@cipherbox/crypto';

const DB_NAME = 'cipherbox-device';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const KEYPAIR_KEY = 'device-ed25519';
const HKDF_INFO = 'cipherbox-device-key-wrap-v1';
const STORAGE_VERSION = 2;

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
 * Derive AES-256-GCM wrapping key from the user's vault private key via HKDF.
 * Same pattern as search-index.service.ts.
 */
async function deriveDeviceWrappingKey(vaultPrivateKey: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    vaultPrivateKey as BufferSource,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(HKDF_INFO),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Load device keypair from IndexedDB.
 *
 * Only loads v2 (encrypted) entries. Returns null for v1 (plaintext legacy)
 * entries, triggering automatic migration via new keypair generation.
 *
 * @param vaultPrivateKey - User's vault private key for HKDF key derivation
 * @returns Keypair if found and decryptable, null otherwise
 */
async function loadDeviceKeypair(
  vaultPrivateKey: Uint8Array
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array } | null> {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);

    const val = await new Promise<Record<string, unknown> | undefined>((resolve, reject) => {
      const request = store.get(KEYPAIR_KEY);
      request.onsuccess = () => resolve(request.result as Record<string, unknown> | undefined);
      request.onerror = () => reject(request.error);
    });

    if (!val || !val.publicKey) return null;

    // v1 (plaintext legacy) — discard and regenerate
    if (val.version !== STORAGE_VERSION) return null;

    // v2 (encrypted) — decrypt the private key
    const wrappingKey = await deriveDeviceWrappingKey(vaultPrivateKey);
    const iv = new Uint8Array(val.iv as number[]);
    const encryptedPrivateKey = new Uint8Array(val.encryptedPrivateKey as number[]);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      wrappingKey,
      encryptedPrivateKey
    );

    return {
      publicKey: new Uint8Array(val.publicKey as number[]),
      privateKey: new Uint8Array(decrypted),
    };
  } catch {
    // IndexedDB unavailable, decryption failed, or corrupt data
    return null;
  }
}

/**
 * Save device keypair to IndexedDB with AES-256-GCM encryption.
 *
 * Converts Uint8Array to plain number arrays before storing
 * to avoid serialization issues across browsers.
 *
 * @param keypair - Device keypair to store
 * @param vaultPrivateKey - User's vault private key for HKDF key derivation
 */
async function saveDeviceKeypair(
  keypair: { publicKey: Uint8Array; privateKey: Uint8Array },
  vaultPrivateKey: Uint8Array
): Promise<void> {
  const wrappingKey = await deriveDeviceWrappingKey(vaultPrivateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    keypair.privateKey as BufferSource
  );

  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);

  store.put(
    {
      publicKey: Array.from(keypair.publicKey),
      encryptedPrivateKey: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      version: STORAGE_VERSION,
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
 * If not found (or legacy v1 plaintext format), generates a new one
 * and persists it encrypted with the vault private key.
 *
 * The returned DeviceKeypair includes:
 * - publicKey: 32-byte Ed25519 public key
 * - privateKey: 32-byte Ed25519 private key (seed)
 * - deviceId: SHA-256 hex of the public key
 *
 * @param vaultPrivateKey - User's vault private key for encrypting at rest.
 *   When undefined (e.g., during REQUIRED_SHARE state before vault is available),
 *   generates a temporary keypair without persisting. The real identity is
 *   created/loaded when useAuth calls this again after login with the vault key.
 * @returns Device keypair with derived device ID
 */
export async function getOrCreateDeviceIdentity(
  vaultPrivateKey?: Uint8Array
): Promise<DeviceKeypair> {
  // Without vault key, return ephemeral identity (not persisted)
  if (!vaultPrivateKey) {
    const keypair = generateDeviceKeypair();
    return keypair;
  }

  // Try loading existing keypair from IndexedDB
  const stored = await loadDeviceKeypair(vaultPrivateKey);
  if (stored) {
    const deviceId = deriveDeviceId(stored.publicKey);
    return {
      publicKey: stored.publicKey,
      privateKey: stored.privateKey,
      deviceId,
    };
  }

  // Generate new keypair and persist (encrypted)
  const keypair = generateDeviceKeypair();
  await saveDeviceKeypair(
    { publicKey: keypair.publicKey, privateKey: keypair.privateKey },
    vaultPrivateKey
  );

  return keypair;
}
