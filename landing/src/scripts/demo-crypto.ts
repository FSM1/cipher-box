/**
 * Real AES-256-GCM encryption/decryption via Web Crypto API for the interactive demo.
 * ECIES wrapping is simulated with pre-computed values since secp256k1
 * isn't natively supported by SubtleCrypto.
 */

// ---- Encoding utilities ----

export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function truncateHex(hex: string, show = 8): string {
  if (hex.length <= show * 2 + 3) return hex;
  return hex.slice(0, show) + '...' + hex.slice(-show);
}

// ---- AES-256-GCM ----

export async function aesGcmEncrypt(
  plaintext: Uint8Array,
  keyBytes: Uint8Array,
  ivBytes: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const result = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes, tagLength: 128 }, key, plaintext);
  const combined = new Uint8Array(result);
  // AES-GCM appends 16-byte auth tag
  const ciphertext = combined.slice(0, combined.length - 16);
  const tag = combined.slice(combined.length - 16);
  return { ciphertext, tag };
}

export async function aesGcmDecrypt(
  ciphertextWithTag: Uint8Array,
  keyBytes: Uint8Array,
  ivBytes: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const result = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
    key,
    ciphertextWithTag
  );
  return new Uint8Array(result);
}

// ---- CID generation (SHA-256 content-addressed) ----

export async function computeCid(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  // CIDv1 base32 prefix "bafybeig" + base32 of the hash
  // Simplified: use hex of hash with realistic prefix
  const hashHex = hexEncode(new Uint8Array(hash));
  return 'bafybeig' + hashHex.slice(0, 44);
}

// ---- Metadata encryption (matches CipherBox wire format) ----

export async function encryptMetadata(
  metadata: object,
  folderKeyBytes: Uint8Array,
  ivBytes: Uint8Array
): Promise<{ iv: string; data: string }> {
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const key = await crypto.subtle.importKey('raw', folderKeyBytes, 'AES-GCM', false, ['encrypt']);
  const result = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivBytes, tagLength: 128 }, key, plaintext);
  return {
    iv: hexEncode(ivBytes),
    data: base64Encode(new Uint8Array(result)),
  };
}

export async function decryptMetadata(
  encrypted: { iv: string; data: string },
  folderKeyBytes: Uint8Array
): Promise<object> {
  const iv = hexDecode(encrypted.iv);
  const ciphertextWithTag = base64Decode(encrypted.data);
  const key = await crypto.subtle.importKey('raw', folderKeyBytes, 'AES-GCM', false, ['decrypt']);
  const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertextWithTag);
  return JSON.parse(new TextDecoder().decode(result));
}
