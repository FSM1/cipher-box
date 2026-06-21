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

  if (cached.signedRecord) {
    try {
      const parsed = withCachedPublicKey(
        await parseIpnsRecordBytes(cached.signedRecord, logger),
        cached.publicKey ?? undefined
      );
      // Use the DB columns as authoritative — sequenceNumber is always
      // incremented by upsertFolderIpns, while the record bytes may contain
      // the client's pre-increment value (e.g. sequence 0 on first publish).
      if (parsed.cid !== cached.latestCid) {
        logger.warn(
          `Cached signed record CID mismatch for ${cached.ipnsName}: signedRecord=${parsed.cid}, latestCid=${cached.latestCid}`
        );
      }
      return { ...parsed, cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn(`Failed to parse cached signed record for ${cached.ipnsName}: ${message}`);
    }
  }

  return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
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
