import { ApiProperty } from '@nestjs/swagger';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
} from 'class-validator';

/**
 * A CID or an IPNS name: url-safe base32/base36/base58 token. Kept
 * deliberately loose — the API is zero-knowledge about the encoding and never
 * parses the multiformat; it only guards the DB column width and rejects
 * obvious junk (whitespace, control chars, oversize).
 */
const CID_OR_NAME = /^[A-Za-z0-9]{1,256}$/;

/** Batch bounds: bulk name waves and sweeps are large but not unbounded. */
export const MAX_BATCH = 1000;
const MAX_CONTENT_CIDS = 1000;

export class RegisterEntryDto {
  @ApiProperty({
    description:
      'The IPNS name to register (libp2p-key CID). Register-first: this row precedes publish.',
    example: 'k51qzi5uqu5dkuzo866rgfkt5nuqo53l6l3l6zk3l6zk3l6zk3l6zk3l6zk3',
  })
  @IsString()
  @MaxLength(128)
  @Matches(CID_OR_NAME, { message: 'ipnsName must be a bare CID/name token' })
  ipnsName!: string;

  @ApiProperty({
    required: false,
    description: 'Current head (metadata) CID this name publishes; omit to register the name only.',
  })
  @IsOptional()
  @IsString()
  @MaxLength(256)
  @Matches(CID_OR_NAME, { message: 'headCid must be a bare CID token' })
  headCid?: string;

  @ApiProperty({
    type: [String],
    description: 'Content CIDs to pin/count under this account (idempotent upsert).',
  })
  @IsArray()
  @ArrayMaxSize(MAX_CONTENT_CIDS)
  @IsString({ each: true })
  @MaxLength(256, { each: true })
  @Matches(CID_OR_NAME, { each: true, message: 'each contentCid must be a bare CID token' })
  contentCids!: string[];
}

/** The register batch: a top-level JSON array `[{ipnsName, headCid?, contentCids[]}]`. */
export const REGISTER_ARRAY_OPTIONS = {
  items: RegisterEntryDto,
  whitelist: true,
  forbidNonWhitelisted: true,
} as const;

/** The retire batch: a top-level JSON array of `[ipnsName | cid]` strings. */
export const RETIRE_ARRAY_OPTIONS = {
  items: String,
} as const;

/**
 * Per-target length cap. `ParseArrayPipe`'s `maxLength` never reaches items, so
 * the guard is enforced explicitly in the controller — 256 matches the widest
 * target column (`pinned_cids.cid`).
 */
export const RETIRE_TARGET_MAX_LENGTH = 256;

export class RegisterResponseDto {
  @ApiProperty({ description: 'Distinct names registered or refreshed in this batch' })
  names!: number;

  @ApiProperty({ description: 'Distinct content CIDs pinned/counted in this batch' })
  cids!: number;
}

export class RetireResponseDto {
  @ApiProperty({ description: 'Inventory + pin rows removed for the caller account' })
  retired!: number;

  @ApiProperty({ description: 'CIDs physically unpinned because global refcount reached zero' })
  unpinned!: number;
}

export class QuotaResponseDto {
  @ApiProperty({ description: 'Bytes currently counted against the account (sum over pin rows)' })
  usedBytes!: number;

  @ApiProperty({ description: 'The account limit: per-account override, else the env default' })
  limitBytes!: number;

  @ApiProperty({
    description: 'True for BYO accounts, whose rows never gate uploads (quota always allows)',
  })
  advisory!: boolean;
}

export class SetByoDto {
  @ApiProperty({ description: 'Enable BYO-IPFS: pin rows become advisory, never quota-enforced' })
  @IsBoolean()
  byo!: boolean;
}

export class ByoResponseDto {
  @ApiProperty({ description: 'The account BYO flag after the update' })
  byo!: boolean;
}

export class DeleteAccountResponseDto {
  @ApiProperty({ description: 'Name-inventory rows retired for the account' })
  namesRetired!: number;

  @ApiProperty({ description: 'Pin rows retired for the account' })
  pinsRetired!: number;

  @ApiProperty({ description: 'Mailbox messages purged for the account' })
  mailboxPurged!: number;

  @ApiProperty({ description: 'CIDs physically unpinned because global refcount reached zero' })
  unpinned!: number;
}
