import { ApiProperty } from '@nestjs/swagger';
import { QUOTA_EXCEEDED, UPLOAD_TOO_LARGE, UploadTooLargeCode } from '../upload-error-codes';

/**
 * The hosted-upload result (blueprint/api.md, Content plane — Ingress). The
 * client references content by the returned CID; `size` is the byte count
 * charged against the account's quota.
 */
export class UploadResponseDto {
  @ApiProperty({ description: 'The content CID Kubo pinned' })
  cid!: string;

  @ApiProperty({ description: 'The pinned size in bytes' })
  size!: number;
}

/** The 413 error body; see `upload-error-codes` for what `code` discriminates. */
export class UploadTooLargeDto {
  @ApiProperty({ enum: [UPLOAD_TOO_LARGE, QUOTA_EXCEEDED], description: 'The refusal cause' })
  code!: UploadTooLargeCode;

  @ApiProperty({ description: 'Human-readable diagnostic; never parse it' })
  message!: string;

  @ApiProperty({ description: 'The HTTP status code', example: 413 })
  statusCode!: number;

  @ApiProperty({ description: 'The HTTP status reason phrase', example: 'Payload Too Large' })
  error!: string;
}
