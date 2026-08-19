import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createTestDeviceKey } from '../testing/device-keys';
import {
  approvalRequestPayload,
  approvalResponsePayload,
  deviceRegistrationPayload,
  verifyDeviceSignature,
} from './device-signature';

/**
 * The identity point. `crypto.verify` accepts it as a public key, and the
 * signature below satisfies the verification equation for EVERY message — a
 * universal forgery, and the reason the subgroup check exists.
 */
const IDENTITY_POINT = `01${'00'.repeat(31)}`;
const UNIVERSAL_FORGERY_SIGNATURE = `${IDENTITY_POINT}${'00'.repeat(32)}`;

/** The eight low-order points; none carries a secret anyone could hold. */
const LOW_ORDER_PUBLIC_KEYS: Array<[string, string]> = [
  ['the identity point', IDENTITY_POINT],
  ['the all-zero encoding', '00'.repeat(32)],
  ['the sign-flipped zero encoding', `${'00'.repeat(31)}80`],
  ['an order-8 point', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['the other order-8 point', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['the order-2 point y = p - 1', `ec${'ff'.repeat(30)}7f`],
];

/** y >= p: not a canonical Ed25519 point encoding, whatever it decodes to. */
const NON_CANONICAL_PUBLIC_KEYS: Array<[string, string]> = [
  ['y = p', `ed${'ff'.repeat(30)}7f`],
  ['y = 2^256 - 1', 'ff'.repeat(32)],
];

describe('verifyDeviceSignature', () => {
  const key = createTestDeviceKey();
  const message = deviceRegistrationPayload(randomUUID(), key.publicKey);
  const signature = key.sign(message);

  it('accepts a genuine Ed25519 signature over the message', () => {
    expect(verifyDeviceSignature(key.publicKey, signature, message)).toBe(true);
  });

  it('refuses a signature made by a different key', () => {
    const other = createTestDeviceKey();
    expect(verifyDeviceSignature(key.publicKey, other.sign(message), message)).toBe(false);
    expect(verifyDeviceSignature(other.publicKey, signature, message)).toBe(false);
  });

  it('refuses a signature over a different message', () => {
    const otherMessage = deviceRegistrationPayload(randomUUID(), key.publicKey);
    expect(verifyDeviceSignature(key.publicKey, key.sign(otherMessage), message)).toBe(false);
  });

  it('refuses a signature over a truncated or extended message', () => {
    const truncated = message.subarray(0, message.length - 1);
    const extended = Buffer.concat([message, Buffer.from('x')]);
    expect(verifyDeviceSignature(key.publicKey, key.sign(truncated), message)).toBe(false);
    expect(verifyDeviceSignature(key.publicKey, key.sign(extended), message)).toBe(false);
    // …and the honest signature does not carry over to either variant.
    expect(verifyDeviceSignature(key.publicKey, signature, truncated)).toBe(false);
    expect(verifyDeviceSignature(key.publicKey, signature, extended)).toBe(false);
  });

  it.each([
    ['uppercase hex', key.publicKey.toUpperCase()],
    ['63 hex chars', key.publicKey.slice(0, 63)],
    ['65 hex chars', `${key.publicKey}0`],
    ['non-hex characters', `${'g'.repeat(2)}${key.publicKey.slice(2)}`],
    ['empty', ''],
    ['0x-prefixed', `0x${key.publicKey.slice(2)}`],
  ])('refuses a public key that is %s, without throwing', (_label, publicKey) => {
    expect(verifyDeviceSignature(publicKey, signature, message)).toBe(false);
  });

  it.each([
    ['uppercase hex', signature.toUpperCase()],
    ['127 hex chars', signature.slice(0, 127)],
    ['129 hex chars', `${signature}0`],
    ['non-hex characters', `zz${signature.slice(2)}`],
    ['empty', ''],
  ])('refuses a signature that is %s, without throwing', (_label, malformed) => {
    expect(verifyDeviceSignature(key.publicKey, malformed, message)).toBe(false);
  });

  /** The real bytes each builder produces; the forgery must fail against all three. */
  const forgeryTargets: Array<[string, Buffer]> = [
    ['registration', deviceRegistrationPayload(randomUUID(), IDENTITY_POINT)],
    ['approval request', approvalRequestPayload(IDENTITY_POINT, `02${'b'.repeat(64)}`)],
    [
      'approval response',
      approvalResponsePayload({
        devicePublicKey: IDENTITY_POINT,
        requestId: randomUUID(),
        decision: 'approve',
        ephemeralPublicKey: `02${'b'.repeat(64)}`,
        sealedFactor: Buffer.alloc(32, 9).toString('base64'),
      }),
    ],
  ];

  it.each(forgeryTargets)(
    'refuses the identity-point universal forgery over the %s payload',
    (_label, payload) => {
      expect(verifyDeviceSignature(IDENTITY_POINT, UNIVERSAL_FORGERY_SIGNATURE, payload)).toBe(
        false
      );
    }
  );

  it.each(LOW_ORDER_PUBLIC_KEYS)(
    'refuses %s, which proves possession of nothing',
    (_label, publicKey) => {
      expect(verifyDeviceSignature(publicKey, UNIVERSAL_FORGERY_SIGNATURE, message)).toBe(false);
      expect(verifyDeviceSignature(publicKey, signature, message)).toBe(false);
    }
  );

  it.each(NON_CANONICAL_PUBLIC_KEYS)(
    'refuses the non-canonical encoding %s, without throwing',
    (_label, publicKey) => {
      expect(verifyDeviceSignature(publicKey, UNIVERSAL_FORGERY_SIGNATURE, message)).toBe(false);
      expect(verifyDeviceSignature(publicKey, signature, message)).toBe(false);
    }
  );

  it.each(forgeryTargets)(
    'still accepts a genuine prime-order key over the %s payload',
    (_label, payload) => {
      const genuine = createTestDeviceKey();
      expect(verifyDeviceSignature(genuine.publicKey, genuine.sign(payload), payload)).toBe(true);
    }
  );
});

describe('signed payloads', () => {
  const userId = '11111111-1111-4111-8111-111111111111';
  const devicePublicKey = 'a'.repeat(64);
  const ephemeralPublicKey = `02${'b'.repeat(64)}`;
  const requestId = '22222222-2222-4222-8222-222222222222';
  const sealedFactor = Buffer.alloc(32, 9).toString('base64');

  type ResponseFields = Parameters<typeof approvalResponsePayload>[0];
  const response: ResponseFields = {
    devicePublicKey,
    requestId,
    decision: 'approve',
    ephemeralPublicKey,
    sealedFactor,
  };

  it('domain-separates the three builders given identical field values', () => {
    const registration = deviceRegistrationPayload(devicePublicKey, devicePublicKey);
    const request = approvalRequestPayload(devicePublicKey, devicePublicKey);
    const responsePayload = approvalResponsePayload({
      devicePublicKey,
      requestId: devicePublicKey,
      decision: 'approve',
      ephemeralPublicKey: devicePublicKey,
      sealedFactor: devicePublicKey,
    });
    const encodings = [registration, request, responsePayload].map((b) => b.toString('hex'));
    expect(new Set(encodings).size).toBe(3);
  });

  it('does not let a signature cross from one builder to another', () => {
    const key = createTestDeviceKey();
    const registration = deviceRegistrationPayload(devicePublicKey, ephemeralPublicKey);
    const request = approvalRequestPayload(devicePublicKey, ephemeralPublicKey);
    const signature = key.sign(registration);
    expect(verifyDeviceSignature(key.publicKey, signature, registration)).toBe(true);
    expect(verifyDeviceSignature(key.publicKey, signature, request)).toBe(false);
  });

  it('changes the registration bytes when any single field changes', () => {
    const base = deviceRegistrationPayload(userId, devicePublicKey);
    expect(deviceRegistrationPayload(requestId, devicePublicKey).equals(base)).toBe(false);
    expect(deviceRegistrationPayload(userId, 'c'.repeat(64)).equals(base)).toBe(false);
  });

  it('changes the request bytes when any single field changes', () => {
    const base = approvalRequestPayload(devicePublicKey, ephemeralPublicKey);
    expect(approvalRequestPayload('c'.repeat(64), ephemeralPublicKey).equals(base)).toBe(false);
    expect(approvalRequestPayload(devicePublicKey, `03${'b'.repeat(64)}`).equals(base)).toBe(false);
  });

  it('changes the response bytes when any single field changes', () => {
    const base = approvalResponsePayload(response);
    const mutations: Array<Partial<ResponseFields>> = [
      { devicePublicKey: 'c'.repeat(64) },
      { requestId: userId },
      { decision: 'deny' },
      { ephemeralPublicKey: `03${'b'.repeat(64)}` },
      { sealedFactor: Buffer.alloc(32, 8).toString('base64') },
      { sealedFactor: '' },
    ];
    for (const mutation of mutations) {
      expect(approvalResponsePayload({ ...response, ...mutation }).equals(base)).toBe(false);
    }
  });

  it('recovers every field by splitting on the separator, so no field can straddle it', () => {
    // The concrete consequence of newline-free field alphabets: the join is
    // reversible, so the parse a verifier implies is unambiguous.
    expect(deviceRegistrationPayload(userId, devicePublicKey).toString('utf8').split('\n')).toEqual(
      ['cipherbox/device-registration/v1', userId, devicePublicKey]
    );
    expect(
      approvalRequestPayload(devicePublicKey, ephemeralPublicKey).toString('utf8').split('\n')
    ).toEqual(['cipherbox/device-approval/request/v1', devicePublicKey, ephemeralPublicKey]);
    expect(approvalResponsePayload(response).toString('utf8').split('\n')).toEqual([
      'cipherbox/device-approval/response/v1',
      devicePublicKey,
      requestId,
      'approve',
      ephemeralPublicKey,
      sealedFactor,
    ]);
  });

  it('never collides two different field tuples across all three builders', () => {
    const hexKeys = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
    const uuids = [userId, requestId];
    const ephemerals = [`02${'b'.repeat(64)}`, `03${'b'.repeat(64)}`];
    const sealed = ['', sealedFactor, Buffer.alloc(16, 1).toString('base64')];

    const payloads: string[] = [];
    for (const a of hexKeys) {
      for (const u of uuids) {
        payloads.push(deviceRegistrationPayload(u, a).toString('hex'));
        for (const e of ephemerals) {
          payloads.push(approvalRequestPayload(a, e).toString('hex'));
          for (const decision of ['approve', 'deny'] as const) {
            for (const s of sealed) {
              payloads.push(
                approvalResponsePayload({
                  devicePublicKey: a,
                  requestId: u,
                  decision,
                  ephemeralPublicKey: e,
                  sealedFactor: s,
                }).toString('hex')
              );
            }
          }
        }
      }
    }

    // Every distinct tuple produced distinct bytes: the request tuple repeats
    // across the `u` loop, so dedupe the inputs the same way the encoding does.
    const distinctInputs =
      hexKeys.length * uuids.length +
      hexKeys.length * ephemerals.length +
      hexKeys.length * uuids.length * ephemerals.length * 2 * sealed.length;
    expect(new Set(payloads).size).toBe(distinctInputs);
  });
});
