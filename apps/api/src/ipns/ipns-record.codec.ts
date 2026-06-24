import { HttpException, HttpStatus, Logger } from '@nestjs/common';
import { parseIpnsRecord } from '@cipherbox/crypto';
import type { FolderIpns } from './entities/folder-ipns.entity';

export interface IpnsRecordFields {
  cid: string;
  sequenceNumber: string;
  signatureV2?: string;
  data?: string;
  pubKey?: string;
}

/**
 * Parse an IPNS record to extract CID and sequence number.
 * Backed by the `ipns` package via @cipherbox/crypto (parseIpnsRecord).
 */
export async function parseIpnsRecordBytes(
  recordBytes: Uint8Array,
  logger: Logger
): Promise<IpnsRecordFields> {
  try {
    const record = await parseIpnsRecord(recordBytes);

    // Extract CID from the Value field (format: /ipfs/<cid>)
    const valuePath = record.value;
    const cidMatch = valuePath.match(/\/ipfs\/([a-zA-Z0-9]+)/);
    if (!cidMatch) {
      logger.error('Failed to extract CID from IPNS record value');
      throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
    }

    const cid = cidMatch[1];
    const sequenceNumber = String(record.sequence ?? 0n);

    // Base64-encode signature fields if present
    const signatureV2 = record.signatureV2
      ? Buffer.from(record.signatureV2).toString('base64')
      : undefined;
    const data = record.data ? Buffer.from(record.data).toString('base64') : undefined;
    const pubKey = record.pubKey ? Buffer.from(record.pubKey).toString('base64') : undefined;

    logger.debug(`Parsed IPNS record: cid=${cid}, sequenceNumber=${sequenceNumber}`);
    return { cid, sequenceNumber, signatureV2, data, pubKey };
  } catch (error) {
    if (error instanceof HttpException) {
      throw error;
    }
    logger.error(`Failed to parse IPNS record: ${error}`);
    throw new HttpException('Invalid IPNS record format', HttpStatus.BAD_GATEWAY);
  }
}

export async function parseCachedRecord(
  cached: FolderIpns | null,
  logger: Logger
): Promise<IpnsRecordFields | null> {
  if (!cached?.latestCid) {
    return null;
  }

  // D-06 (Plan 60-05): null signedRecord → return null (→ 404 to caller).
  // A row without a signed record cannot be served as authoritative; the client
  // cannot verify an unsigned CID and must not act on it.
  if (!cached.signedRecord) {
    return null;
  }

  try {
    const parsed = await parseIpnsRecordBytes(cached.signedRecord, logger);
    // D-06 (Plan 60-05): discard on CID or sequence mismatch between the signed
    // record bytes and the DB columns — a mismatch means the row is inconsistent
    // and must not be served.  Warn and return null; the caller will 404.
    if (parsed.cid !== cached.latestCid) {
      logger.warn(
        `Cached signed record CID mismatch for ${cached.ipnsName}: signedRecord=${parsed.cid}, latestCid=${cached.latestCid} — discarding cached result`
      );
      return null;
    }
    // DB columns are authoritative for sequenceNumber (upsertFolderIpns always
    // increments it, while the embedded bytes reflect the client's pre-increment value).
    return { ...parsed, cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`Failed to parse cached signed record for ${cached.ipnsName}: ${message}`);
    return null;
  }
}

export function withCachedPublicKey(
  result: IpnsRecordFields,
  publicKey?: Buffer
): IpnsRecordFields {
  if (result.pubKey || !result.signatureV2 || !result.data || !publicKey) {
    return result;
  }

  return {
    ...result,
    pubKey: publicKey.toString('base64'),
  };
}
