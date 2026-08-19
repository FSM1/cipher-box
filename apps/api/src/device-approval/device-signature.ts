/**
 * The signed payloads of the bound rendezvous (ADR 0009 D4), defined once so the
 * server verifies exactly what a client is told to sign.
 *
 * Each is newline-joined and domain-separated. Every field is constrained by its
 * DTO to hex, a uuid, a fixed decision literal, or base64, none of whose
 * alphabets contains a newline, so no field can straddle the separator.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { createPublicKey, verify } from 'node:crypto';

/** How an approver answered. The wire spelling is fixed by the payload builder. */
export type ApprovalDecision = 'approve' | 'deny';

/** Raw Ed25519 device identity public key: 32 bytes, lowercase hex. */
export const DEVICE_PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;

/** Ed25519 signature: 64 bytes, lowercase hex. */
export const DEVICE_SIGNATURE_HEX = /^[0-9a-f]{128}$/;

/** SPKI DER header for an id-Ed25519 subjectPublicKey (RFC 8410 §4). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * A genuine Ed25519 public key: canonically encoded, on the curve, and in the
 * prime-order subgroup.
 *
 * The subgroup check is what makes a signature evidence of possession. OpenSSL
 * verifies against a low-order key without complaint, and for such a key a
 * signature exists that satisfies the verification equation for EVERY message —
 * so a caller could register one and sign anything for it while holding no
 * secret at all, which is exactly the proof `POST /devices` claims to take.
 * `isSmallOrder` alone is not enough: the identity point is small-order AND
 * torsion-free, so both must hold.
 */
function isGenuineEd25519PublicKey(publicKey: Buffer): boolean {
  try {
    const point = ed25519.Point.fromBytes(publicKey);
    return !point.isSmallOrder() && point.isTorsionFree();
  } catch {
    return false;
  }
}

/**
 * Verify an Ed25519 device signature over `message`, fail-closed on anything
 * malformed. Returns a boolean rather than throwing so callers answer with one
 * indistinguishable refusal — a caller must never learn *why* a signature
 * failed.
 */
export function verifyDeviceSignature(
  devicePublicKeyHex: string,
  signatureHex: string,
  message: Buffer
): boolean {
  if (!DEVICE_PUBLIC_KEY_HEX.test(devicePublicKeyHex)) return false;
  if (!DEVICE_SIGNATURE_HEX.test(signatureHex)) return false;
  const publicKey = Buffer.from(devicePublicKeyHex, 'hex');
  if (!isGenuineEd25519PublicKey(publicKey)) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: 'der',
      type: 'spki',
    });
    return verify(null, message, key, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

export function deviceRegistrationPayload(userId: string, devicePublicKey: string): Buffer {
  return Buffer.from(
    ['cipherbox/device-registration/v1', userId, devicePublicKey].join('\n'),
    'utf8'
  );
}

/**
 * What the requesting device signs: the ephemeral public key it is asking the
 * approver to seal to, bound to its own identity key. A relay that substitutes
 * the ephemeral key invalidates this signature, so the approver can check the
 * binding itself instead of trusting what the bulletin board echoed back.
 */
export function approvalRequestPayload(
  devicePublicKey: string,
  ephemeralPublicKey: string
): Buffer {
  return Buffer.from(
    ['cipherbox/device-approval/request/v1', devicePublicKey, ephemeralPublicKey].join('\n'),
    'utf8'
  );
}

/** The approver's decision, bound to the request, the ephemeral key, and the sealed bytes. */
export function approvalResponsePayload(input: {
  devicePublicKey: string;
  requestId: string;
  decision: ApprovalDecision;
  ephemeralPublicKey: string;
  sealedFactor: string;
}): Buffer {
  return Buffer.from(
    [
      'cipherbox/device-approval/response/v1',
      input.devicePublicKey,
      input.requestId,
      input.decision,
      input.ephemeralPublicKey,
      input.sealedFactor,
    ].join('\n'),
    'utf8'
  );
}
