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

    // Validate payload shape before touching crypto
    const publicKeyArr = Array.isArray(val?.publicKey) ? (val.publicKey as number[]) : null;
    const ivArr = Array.isArray(val?.iv) ? (val.iv as number[]) : null;
    const encryptedArr = Array.isArray(val?.encryptedPrivateKey)
      ? (val.encryptedPrivateKey as number[])
      : null;
    if (!publicKeyArr || publicKeyArr.length !== 32) return null;

    // v1 (plaintext legacy) — discard and regenerate
    if (val?.version !== STORAGE_VERSION) return null;

    // v2 (encrypted) — validate remaining fields
    if (!ivArr || ivArr.length !== 12) return null;
    if (!encryptedArr || encryptedArr.length < 48) return null; // 32-byte plaintext + 16-byte GCM tag

    // Decrypt the private key
    const wrappingKey = await deriveDeviceWrappingKey(vaultPrivateKey);
    const iv = new Uint8Array(ivArr);
    const encryptedPrivateKey = new Uint8Array(encryptedArr);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      wrappingKey,
      encryptedPrivateKey
    );

    const privateKey = new Uint8Array(decrypted);
    if (privateKey.length !== 32) return null;

    return {
      publicKey: new Uint8Array(publicKeyArr),
      privateKey,
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
 * Module-scoped fallback identity for when IndexedDB persistence fails.
 * Scoped to the vault key hash to prevent cross-account reuse if a different
 * user logs in within the same browser session (tab reuse without reload).
 */
let sessionFallback: { keypair: DeviceKeypair; vaultKeyHash: string } | null = null;

/**
 * In-flight promise for persisted identity creation. Deduplicates concurrent
 * calls so only one keypair is generated and saved to IndexedDB.
 * Scoped to vault key hash to prevent cross-account deduplication.
 */
let persistedInFlight: { promise: Promise<DeviceKeypair>; vaultKeyHash: string } | null = null;

/**
 * Hash the entire vault key and use the first 8 bytes of the digest to scope
 * the session fallback, avoiding storage of raw key material in module scope.
 */
async function hashVaultKey(vaultPrivateKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', vaultPrivateKey as BufferSource);
  return Array.from(new Uint8Array(digest.slice(0, 8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Request type for getOrCreateDeviceIdentity.
 *
 * - `persisted`: Load or create a device keypair encrypted in IndexedDB.
 * - `ephemeral`: Generate a temporary in-memory keypair (not persisted).
 *   Use only during REQUIRED_SHARE state before the vault key is available.
 */
export type DeviceIdentityRequest =
  | { mode: 'persisted'; vaultPrivateKey: Uint8Array }
  | { mode: 'ephemeral' };

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
 * @param request - Discriminated union specifying whether to persist or use ephemeral identity.
 *   `{ mode: 'persisted', vaultPrivateKey }` encrypts the keypair at rest in IndexedDB.
 *   `{ mode: 'ephemeral' }` generates a temporary keypair (e.g., during REQUIRED_SHARE
 *   state before vault is available). The real identity is created/loaded when useAuth
 *   calls this again after login with the vault key.
 * @returns Device keypair with derived device ID
 */
export async function getOrCreateDeviceIdentity(
  request: DeviceIdentityRequest
): Promise<DeviceKeypair> {
  // Ephemeral mode: return in-memory identity (not persisted)
  if (request.mode === 'ephemeral') {
    const keypair = generateDeviceKeypair();
    return keypair;
  }

  // Deduplicate concurrent persisted-mode calls for the same vault key
  const vaultKeyHash = await hashVaultKey(request.vaultPrivateKey);
  if (persistedInFlight && persistedInFlight.vaultKeyHash === vaultKeyHash) {
    return persistedInFlight.promise;
  }

  const promise = resolvePersistedIdentity(request.vaultPrivateKey, vaultKeyHash);
  persistedInFlight = { promise, vaultKeyHash };
  try {
    return await promise;
  } finally {
    persistedInFlight = null;
  }
}

/**
 * Internal: resolve the persisted device identity.
 * Separated from the public API so the deduplication wrapper stays clean.
 */
async function resolvePersistedIdentity(
  vaultPrivateKey: Uint8Array,
  vaultKeyHash: string
): Promise<DeviceKeypair> {
  // Try loading existing keypair from IndexedDB
  const stored = await loadDeviceKeypair(vaultPrivateKey);
  if (stored) {
    const deviceId = deriveDeviceId(stored.publicKey);
    // IDB is working — clear any session fallback
    sessionFallback = null;
    return {
      publicKey: stored.publicKey,
      privateKey: stored.privateKey,
      deviceId,
    };
  }

  // Return session fallback if IDB previously failed for this vault
  if (sessionFallback && sessionFallback.vaultKeyHash === vaultKeyHash) {
    return sessionFallback.keypair;
  }

  // Different vault or no fallback — clear stale entry
  sessionFallback = null;

  // Generate new keypair and persist (encrypted)
  const keypair = generateDeviceKeypair();
  try {
    await saveDeviceKeypair(
      { publicKey: keypair.publicKey, privateKey: keypair.privateKey },
      vaultPrivateKey
    );
  } catch {
    // IndexedDB unavailable or write failed; keep identity stable for this session.
    sessionFallback = { keypair, vaultKeyHash };
  }

  return keypair;
}
