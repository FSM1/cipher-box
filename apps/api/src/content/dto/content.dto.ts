import { ApiProperty } from '@nestjs/swagger';

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
