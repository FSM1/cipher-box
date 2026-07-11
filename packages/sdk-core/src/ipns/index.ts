/**
 * IPNS Service - Record creation, publishing, and resolution
 *
 * Extracted from: apps/web/src/services/ipns.service.ts
 * Change: Uses @cipherbox/api-client generated functions instead of web app local imports.
 * The ipns.service.ts was already clean (no store deps), so the extraction is straightforward.
 */

import { createIpnsRecord, marshalIpnsRecord, IPNS_SIGNATURE_PREFIX } from '@cipherbox/core';
import {
  verifyEd25519,
  concatBytes,
  deriveEd25519PublicKey,
  deriveIpnsName,
} from '@cipherbox/crypto';
import { decode as cborDecode } from 'cborg';
import {
  ipnsControllerPublishRecord,
  ipnsControllerPublishBatch,
  ipnsControllerResolveRecord,
} from '@cipherbox/api-client';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';

/**
 * Create an IPNS record locally and publish via backend.
 *
 * The record is signed locally using the Ed25519 private key, then
 * the backend relays it to the IPFS network via delegated routing.
 *
 * @param params.ipnsPrivateKey - 32-byte Ed25519 private key seed
 * @param params.ipnsName - IPNS name (k51.../bafzaa... format)
 * @param params.metadataCid - CID of the encrypted metadata blob
 * @param params.sequenceNumber - Sequence number for this publish
 * @param params.encryptedIpnsPrivateKey - Hex ECIES-wrapped key for TEE (first publish only)
 * @param params.keyEpoch - TEE key epoch (required with encryptedIpnsPrivateKey)
 * @param params.expectedSequenceNumber - Pre-increment sequence number for conflict detection (folder records only)
 * @param params.generation - Content generation epoch (bigint as string). When provided, the server rejects publishes with a lower generation number (TEE-07 forward-only gate). Omit for non-rotation publishes.
 */
export async function createAndPublishIpnsRecord(params: {
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  metadataCid: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  expectedSequenceNumber?: string;
  generation?: string;
  ctx?: SdkContext;
}): Promise<{ success: boolean; sequenceNumber: bigint; tombstoned?: boolean }> {
  return withPerf('ipns:publish', async () => {
    // T-47-01 / D-05: caller-owns-key convention. This is a CALLEE that receives a
    // caller-owned `ipnsPrivateKey` buffer — it MUST NOT zero it. Callers reuse the
    // same buffer across operations (the SDK client caches per-folder IPNS keys in
    // its folderTree and passes them on every mutation; publishWithCas reuses the
    // buffer across CAS retries). Zeroing here corrupted those long-lived buffers,
    // so the next publish derived the public key from all-zero bytes and the server
    // rejected it (400 "publicKey does not correspond to the given ipnsName").
    // Terminal owners zero the key themselves: the client on destroy(), transient
    // unwrapped keys via clearBytes()/finally, publishVaultKeyBlob / shared-write on
    // their freshly-derived keypairs. This matches publishWithCas's documented
    // contract ("NEVER zeroes key material — callers are responsible") and
    // updateFolderMetadataAndPublish ("CALLER RETAINS OWNERSHIP").

    // 1. Create IPNS record pointing to /ipfs/{metadataCid}
    // 24 hour lifetime (will be republished by TEE every 3 hours)
    const record = await createIpnsRecord(
      params.ipnsPrivateKey,
      `/ipfs/${params.metadataCid}`,
      params.sequenceNumber,
      24 * 60 * 60 * 1000 // 24 hours in ms
    );

    // 2. Marshal to bytes for transport
    const recordBytes = marshalIpnsRecord(record);
    const publicKeyBytes = params.ipnsPublicKey ?? deriveEd25519PublicKey(params.ipnsPrivateKey);

    // 3. Base64 encode for API transmission (loop-based to avoid call stack overflow on large records)
    let binary = '';
    for (let i = 0; i < recordBytes.length; i++) {
      binary += String.fromCharCode(recordBytes[i]);
    }
    const recordBase64 = btoa(binary);
    binary = '';
    for (let i = 0; i < publicKeyBytes.length; i++) {
      binary += String.fromCharCode(publicKeyBytes[i]);
    }
    const publicKey = btoa(binary);

    // 4. Call backend API to relay to IPFS network
    const apiOptions = params.ctx?.axiosInstance
      ? { _axiosInstance: params.ctx.axiosInstance }
      : undefined;
    let response;
    try {
      response = await ipnsControllerPublishRecord(
        {
          ipnsName: params.ipnsName,
          record: recordBase64,
          publicKey,
          metadataCid: params.metadataCid,
          encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
          keyEpoch: params.keyEpoch,
          expectedSequenceNumber: params.expectedSequenceNumber,
          generation: params.generation,
        },
        apiOptions
      );
    } catch (error) {
      // SC4(a): a 410 (IPNS_TOMBSTONED, apps/api ipns.service.ts) means the co-writer's
      // IPNS name was rotated out from under it — surface a real, catchable signal
      // instead of letting a raw AxiosError propagate. Mirrors the 404-detection idiom
      // in resolveIpnsRecord (see the catch block below). All other errors rethrow
      // unchanged — this must not become a silent-swallow of publish failures.
      const anyError = error as Error & { status?: number; response?: { status?: number } };
      const status = anyError.status ?? anyError.response?.status;
      if (status === 410) {
        return { success: false, sequenceNumber: 0n, tombstoned: true };
      }
      throw error;
    }

    return {
      success: response.success,
      sequenceNumber: BigInt(response.sequenceNumber),
    };
  });
}

/**
 * Batch publish multiple IPNS records in a single API call.
 *
 * Sends all records (folder and/or file) to the batch endpoint,
 * which processes them with concurrency-limited parallelism.
 * Partial success is allowed: individual failures do not fail the batch.
 *
 * @param records - Array of IPNS record payloads to publish
 * @returns Success and failure counts
 */
export async function batchPublishIpnsRecords(
  records: Array<{
    ipnsName: string;
    recordBase64: string;
    publicKey?: string;
    metadataCid: string;
    encryptedIpnsPrivateKey?: string;
    keyEpoch?: number;
    /** Pre-increment sequence number for conflict detection (folder records only) */
    expectedSequenceNumber?: string;
  }>,
  ctx?: SdkContext
): Promise<{ totalSucceeded: number; totalFailed: number }> {
  return withPerf('ipns:batch-publish', async () => {
    const apiOptions = ctx?.axiosInstance ? { _axiosInstance: ctx.axiosInstance } : undefined;
    const response = await ipnsControllerPublishBatch(
      {
        records: records.map((r) => ({
          ipnsName: r.ipnsName,
          record: r.recordBase64,
          publicKey: r.publicKey,
          metadataCid: r.metadataCid,
          encryptedIpnsPrivateKey: r.encryptedIpnsPrivateKey,
          keyEpoch: r.keyEpoch,
          expectedSequenceNumber: r.expectedSequenceNumber,
        })),
      },
      apiOptions
    );

    return {
      totalSucceeded: response.totalSucceeded,
      totalFailed: response.totalFailed,
    };
  });
}

/**
 * Parse a fixed-format RFC3339 timestamp string to Unix seconds.
 *
 * The IPNS Validity field uses the format produced by the Rust `format_validity_timestamp`
 * helper (`crates/core/src/ipns.rs`): `"YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ"` (nanoseconds, UTC).
 * Nanoseconds are optional: `"YYYY-MM-DDTHH:MM:SSZ"` also parses.
 *
 * This is a manual, strict parser that mirrors `parse_rfc3339_to_unix_secs` in
 * `crates/api-client/src/ipns.rs` branch-for-branch — it intentionally does NOT delegate to
 * `new Date(s)`, which tolerates a wide superset of non-canonical formats (timezone offsets,
 * two-digit years, whitespace-separated date/time, rolling an impossible calendar date like
 * February 30 forward into March) that the Rust verifier rejects. Any divergence here is a
 * cross-language verification differential (T-75-06).
 *
 * Returns `null` for any malformed/out-of-range input; callers must treat this as fail-closed
 * (do not add a date-library dependency — see the port PATTERNS note).
 */
export function parseRfc3339ToUnixSecs(s: string): number | null {
  // Expected format: "2026-01-01T00:00:00.000000000Z" (nanoseconds optional, must end with Z).
  if (!s.endsWith('Z')) {
    return null;
  }
  const withoutZ = s.slice(0, -1);

  const tIndex = withoutZ.indexOf('T');
  if (tIndex === -1) {
    return null;
  }
  const datePart = withoutZ.slice(0, tIndex);
  const timePart = withoutZ.slice(tIndex + 1);

  const dateParts = datePart.split('-');
  // Reject trailing date components (e.g. "2026-01-01-99"). Exactly 3 parts required.
  if (dateParts.length !== 3) {
    return null;
  }
  const [yearStr, monthStr, dayStr] = dateParts;
  // Fixed-width RFC3339 date fields: YYYY (4) - MM (2) - DD (2). Fixed lengths reject a
  // leading sign ("+2099"), non-4-digit / i64-overflowing years, and 1-digit months —
  // matching the Rust parser (crates/api-client/src/ipns.rs) exactly. Real records from
  // format_validity_timestamp are always zero-padded, so this never false-rejects.
  if (!isFixedDigits(yearStr, 4) || !isFixedDigits(monthStr, 2) || !isFixedDigits(dayStr, 2)) {
    return null;
  }
  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);

  // Split off nanoseconds if present; a present fractional part must be non-empty and
  // all ASCII digits (reject junk like "00:00:00." or extra separators).
  const dotIndex = timePart.indexOf('.');
  const timeNoNanos = dotIndex === -1 ? timePart : timePart.slice(0, dotIndex);
  if (dotIndex !== -1) {
    const frac = timePart.slice(dotIndex + 1);
    if (frac.length === 0 || !isAllDigits(frac)) {
      return null;
    }
  }

  const timeParts = timeNoNanos.split(':');
  // Reject trailing time components (e.g. "00:00:00:99"). Exactly 3 parts required.
  if (timeParts.length !== 3) {
    return null;
  }
  const [hourStr, minuteStr, secondStr] = timeParts;
  // Fixed-width RFC3339 time fields: HH (2) : MM (2) : SS (2). Mirrors the Rust parser.
  if (!isFixedDigits(hourStr, 2) || !isFixedDigits(minuteStr, 2) || !isFixedDigits(secondStr, 2)) {
    return null;
  }
  const hour = Number(hourStr);
  const minute = Number(minuteStr);
  const second = Number(secondStr);

  // Range + leap-aware day-of-month validation. Reject impossible dates (e.g. 2026-02-31)
  // rather than silently rolling them into the next month, which would EXTEND the record's
  // apparent validity — the opposite of fail-closed.
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonthByMonth: Record<number, number> = {
    1: 31,
    2: isLeap ? 29 : 28,
    3: 31,
    4: 30,
    5: 31,
    6: 30,
    7: 31,
    8: 31,
    9: 30,
    10: 31,
    11: 30,
    12: 31,
  };
  const daysInMonth = daysInMonthByMonth[month];
  if (day > daysInMonth) {
    return null;
  }

  // Compute days since Unix epoch using the Hinnant civil_from_days algorithm (inverted),
  // matching the Rust implementation exactly (crates/api-client/src/ipns.rs).
  const y = month <= 2 ? year - 1 : year;
  const m = month <= 2 ? month + 9 : month - 3;
  const era = Math.floor((y >= 0 ? y : y - 399) / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * m + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const daysSinceEpoch = era * 146097 + doe - 719468;

  if (daysSinceEpoch < 0) {
    return null; // Pre-epoch timestamp — treat as expired.
  }

  return daysSinceEpoch * 86400 + hour * 3600 + minute * 60 + second;
}

function isAllDigits(s: string): boolean {
  return s.length > 0 && /^[0-9]+$/.test(s);
}

/** Exactly `len` ASCII digits — enforces fixed-width RFC3339 fields for cross-language parity. */
function isFixedDigits(s: string, len: number): boolean {
  return s.length === len && isAllDigits(s);
}

/**
 * Verify the Ed25519 signature on an IPNS record.
 * Per IPFS spec, the signature is over "ipns-signature:" + cborData.
 *
 * @param signatureV2 - base64 Ed25519 signature (64 bytes)
 * @param data - base64 CBOR data that was signed
 * @param pubKey - base64 raw Ed25519 public key (32 bytes)
 * @returns true if valid
 */
export async function verifyIpnsSignature(
  signatureV2: string,
  data: string,
  pubKey: string
): Promise<boolean> {
  const sigBytes = Uint8Array.from(atob(signatureV2), (c) => c.charCodeAt(0));
  const dataBytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
  const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));

  // Per IPFS IPNS spec, signature is over "ipns-signature:" + cborData
  const signedData = concatBytes(IPNS_SIGNATURE_PREFIX, dataBytes);
  return verifyEd25519(sigBytes, signedData, pubKeyBytes);
}

/**
 * Resolve an IPNS name to its current CID and sequence number.
 *
 * Calls backend API which relays to the delegated routing service for resolution.
 * When the response includes IPNS signature data (from delegated routing),
 * verifies the Ed25519 signature before trusting the CID.
 *
 * @param ipnsName - IPNS name to resolve (k51.../bafzaa... format)
 * @returns Current CID, sequence number, and signature verification status, or null if not found
 */
export async function resolveIpnsRecord(
  ipnsName: string,
  ctx?: SdkContext
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return withPerf('ipns:resolve', async () => {
    try {
      const apiOptions = ctx?.axiosInstance ? { _axiosInstance: ctx.axiosInstance } : undefined;
      const response = await ipnsControllerResolveRecord({ ipnsName }, apiOptions);

      if (!response.success) {
        return null;
      }

      // Verify IPNS signature. D-02: present-but-invalid → throw (fail closed).
      // D-03: ALL fields absent → allow + flag (legacy record; DB CID is authoritative).
      // Partial fields (some but not all three) → fail closed: unverifiable signature
      // material must not be downgraded to the legacy allow path (field-stripping bypass).
      let signatureVerified = false;
      const { signatureV2, data, pubKey } = response;
      const hasSignatureV2 = signatureV2 != null;
      const hasData = data != null;
      const hasPubKey = pubKey != null;
      if (hasSignatureV2 || hasData || hasPubKey) {
        if (!hasSignatureV2 || !hasData || !hasPubKey || !signatureV2 || !data || !pubKey) {
          throw new Error(
            'IPNS resolve returned incomplete signature data - record cannot be verified'
          );
        }

        const valid = await verifyIpnsSignature(signatureV2, data, pubKey);
        if (!valid) {
          throw new Error('IPNS signature verification failed - record may be tampered');
        }

        // Verify the returned public key derives to the requested IPNS name
        const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));
        const derivedName = await deriveIpnsName(pubKeyBytes);
        if (derivedName !== ipnsName) {
          throw new Error(
            'IPNS public key does not match requested name - possible key substitution'
          );
        }

        signatureVerified = true;

        // D-07/D-08: bind the signed CBOR `data` back to the response cid and sequenceNumber.
        // The Ed25519 signature only covers the CBOR `data` field — the top-level cid and
        // sequenceNumber are NOT covered and can be tampered independently by a MITM server.
        // Decode the signed CBOR and require that its embedded Value matches the response cid
        // and its embedded Sequence matches the response sequenceNumber.
        const dataBytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
        // Phase 75 parity hardening: reject duplicate CBOR map keys. cborg defaults to
        // last-wins, which would let a signed record with e.g. `ValidityType:[1,0]` decode
        // to 0 (accepted) while the Rust decoder (decode_ipns_cbor_validity/_data) rejects
        // duplicate keys outright — a verdict split-brain. Reject on both sides identically.
        const cborFields = cborDecode(dataBytes, {
          rejectDuplicateMapKeys: true,
        }) as Record<string, unknown>;

        // D-08: embedded value must be "/ipfs/<response.cid>"
        const embeddedValue =
          cborFields['Value'] instanceof Uint8Array
            ? new TextDecoder().decode(cborFields['Value'])
            : null;
        const expectedValue = `/ipfs/${response.cid}`;
        if (embeddedValue !== expectedValue) {
          throw new Error(
            `IPNS cid binding mismatch: embedded=${embeddedValue}, response cid=${response.cid}`
          );
        }

        // D-07 (Plan 60-03): embedded sequence must equal response sequenceNumber — strict equality.
        // The first-publish skew disjunct (embedded=0, resp=1) is removed per D-05: all first-publish
        // producers now embed sequence 1 (Plan 60-02), so the old skew window no longer exists.
        const embeddedSeq = cborFields['Sequence'];
        if (embeddedSeq === undefined || embeddedSeq === null) {
          throw new Error(
            `IPNS sequence binding mismatch: embedded=undefined, response sequenceNumber=${response.sequenceNumber}`
          );
        }
        if (typeof embeddedSeq !== 'number' && typeof embeddedSeq !== 'bigint') {
          throw new Error(
            `IPNS sequence binding mismatch: embedded type ${typeof embeddedSeq}, response sequenceNumber=${response.sequenceNumber}`
          );
        }
        const embeddedSeqBigInt =
          typeof embeddedSeq === 'bigint' ? embeddedSeq : BigInt(embeddedSeq as number);
        const responseSeqBigInt = BigInt(response.sequenceNumber);
        // D-05 strict equality (Plan 60-03): no skew disjunct.
        const seqOk = embeddedSeqBigInt === responseSeqBigInt;
        if (!seqOk) {
          throw new Error(
            `IPNS sequence binding mismatch: embedded=${embeddedSeq}, response sequenceNumber=${response.sequenceNumber}`
          );
        }

        // D-07 (Plan 60-03): parse CBOR Validity field and enforce EOL/expiry.
        // Validity is a Uint8Array containing an RFC3339 timestamp string (nanosecond precision).
        // Apply a 5-minute clock skew buffer (matching the Rust side): reject when
        // expiry < now - 5min. Fail-closed: an absent, non-bytes, or unparseable Validity is
        // rejected — mirrors the Rust verifier (crates/api-client/src/ipns.rs: missing Validity
        // is treated as expired) so both layers reach an identical verdict for every input.
        const validityBytes = cborFields['Validity'];
        if (!(validityBytes instanceof Uint8Array)) {
          throw new Error('IPNS record has no Validity field — fail closed');
        }

        // Phase 75 (SC1 / T-75-07): bind ValidityType == 0 (EOL) before treating Validity as an
        // expiry timestamp. Fail closed on absent or non-zero ValidityType — a conformant
        // signer always emits ValidityType 0 today, so this is defense-in-depth, not a
        // behavior change for well-formed records. Mirrors the Rust bind_verified gate
        // (crates/api-client/src/ipns.rs) so both layers reject the same non-EOL records.
        const validityType = cborFields['ValidityType'];
        if (validityType === undefined || validityType === null) {
          throw new Error('IPNS record has no ValidityType field — fail closed');
        }
        const validityTypeNum =
          typeof validityType === 'bigint' ? Number(validityType) : validityType;
        if (validityTypeNum !== 0) {
          throw new Error(`IPNS record has non-EOL ValidityType: ${String(validityType)}`);
        }

        const validityStr = new TextDecoder().decode(validityBytes);
        // Phase 75 (SC1 / T-75-06): strict RFC3339 parse mirroring the Rust verifier's
        // parse_rfc3339_to_unix_secs branch-for-branch. Replaces the previous
        // new Date(validityStr).getTime() loose parse, which accepted a wide superset of
        // non-canonical formats Rust rejects.
        const expirySecs = parseRfc3339ToUnixSecs(validityStr);
        if (expirySecs === null) {
          throw new Error(`IPNS record has unparseable Validity field: ${validityStr}`);
        }
        const expiryMs = expirySecs * 1000;
        const skewBufferMs = 5 * 60 * 1000; // 5 minutes
        if (expiryMs < Date.now() - skewBufferMs) {
          throw new Error(`IPNS record expired: validity=${validityStr}`);
        }
      } else {
        // D-05 (Plan 60-03): fail closed when all three signature fields are absent.
        // The legacy console.warn + soft-return path is removed. A record without signature
        // fields cannot be verified and must never be trusted as a non-error state.
        throw new Error('IPNS resolve returned without signature fields — fail closed');
      }

      return {
        cid: response.cid,
        sequenceNumber: BigInt(response.sequenceNumber),
        signatureVerified,
      };
    } catch (error) {
      // 404 means IPNS name not found - return null
      // Other errors should propagate (including signature verification failures)
      if (error instanceof Error) {
        const anyError = error as Error & { status?: number; response?: { status?: number } };
        const status = anyError.status ?? anyError.response?.status;
        if (status === 404) {
          return null;
        }
      }
      throw error;
    }
  });
}
