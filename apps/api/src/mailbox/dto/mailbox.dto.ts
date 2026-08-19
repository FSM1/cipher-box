import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches, MaxLength } from 'class-validator';
import { BASE64_RE } from '../../common/patterns';

const HEX_PUBLIC_KEY = /^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{1,128}$/;

/**
 * A base64 blob string longer than this cannot decode to <= 8 KiB, so the DTO
 * rejects it cheaply; the service still enforces the exact decoded-byte bound.
 */
const MAX_BLOB_BASE64_LENGTH = 12000;

export class PostMessageDto {
  @ApiProperty({
    description: 'Recipient identity publicKey, hex secp256k1 (compressed or uncompressed)',
    example: '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc',
  })
  @IsString()
  @Matches(HEX_PUBLIC_KEY, { message: 'recipientPublicKey must be a hex secp256k1 public key' })
  recipientPublicKey!: string;

  @ApiProperty({
    description:
      'HPKE-sealed opaque payload, base64 (decodes to <= 8 KiB). Never inspected server-side.',
  })
  @IsString()
  @MaxLength(MAX_BLOB_BASE64_LENGTH)
  @Matches(BASE64_RE, { message: 'blob must be base64' })
  blob!: string;

  @ApiProperty({
    description:
      'Sender-supplied idempotency key; a replay returns the original message id. MUST be a ' +
      'high-entropy per-message random value: it is blended into a one-way sender digest, and a ' +
      'low-entropy key would let a server-side observer brute-force the sender→recipient edge.',
  })
  @IsString()
  @Matches(IDEMPOTENCY_KEY, {
    message: 'idempotencyKey must be 1-128 url-safe characters',
  })
  idempotencyKey!: string;
}

export class PostMessageResponseDto {
  @ApiProperty({ description: 'Server-assigned message id' })
  id!: string;
}

export class MailboxMessageDto {
  @ApiProperty({ description: 'Message id; ack deletes by this id' })
  id!: string;

  @ApiProperty({ description: 'Post time, ISO 8601' })
  receivedAt!: string;

  @ApiProperty({ description: 'HPKE-sealed opaque payload, base64 (owner-signed inside the seal)' })
  blob!: string;
}

export class PollResponseDto {
  @ApiProperty({ type: [MailboxMessageDto], description: 'Pending messages, oldest first' })
  messages!: MailboxMessageDto[];
}

export class AckResponseDto {
  @ApiProperty()
  success!: boolean;
}
