import { ApiProperty } from '@nestjs/swagger';

/**
 * Response for creating or listing invites (sharer's view).
 */
export class InviteResponseDto {
  @ApiProperty({ description: 'Invite UUID (for management operations like revoke)' })
  id!: string;

  @ApiProperty({ description: 'Invite token (URL-safe base64)' })
  token!: string;

  @ApiProperty({ description: 'IPNS name of the root shared node' })
  shareRootIpnsName!: string;

  @ApiProperty({ description: 'UUID of the root shared node' })
  rootNodeId!: string;

  @ApiProperty({ description: 'Generation of the root node at invite creation (numeric string)' })
  rootGeneration!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the display name, or null if not provided',
    type: String,
    nullable: true,
  })
  itemNameEncrypted!: string | null;

  @ApiProperty({ enum: ['active', 'claimed', 'revoked'] })
  status!: string;

  @ApiProperty({ description: 'When the invite expires', type: 'string', format: 'date-time' })
  expiresAt!: Date;

  @ApiProperty({ description: 'When the invite was created', type: 'string', format: 'date-time' })
  createdAt!: Date;
}

/**
 * Response for the public invite status check (no auth required).
 * Returns only the status -- opaque before authentication.
 */
export class InviteStatusResponseDto {
  @ApiProperty({
    enum: ['active'],
    description:
      'Invite status. Only "active" is returned; all other states result in 404 ' +
      'to prevent token-existence oracle attacks.',
  })
  status!: string;
}

/**
 * Response for the authenticated invite data fetch (claim flow).
 * Returns the encrypted key ciphertext and root identity needed by the client.
 */
export class InviteDataResponseDto {
  @ApiProperty({
    enum: ['active', 'expired', 'claimed', 'revoked'],
    description: 'Current status of the invite',
  })
  status!: string;

  @ApiProperty({
    description: 'Hex-encoded root readKey wrapped with ephemeral public key',
  })
  encryptedReadKey!: string;

  @ApiProperty({
    description:
      'Hex-encoded ECIES encrypted key for write access wrapped with ephemeral public key. ' +
      'Null for read-only invites.',
    type: String,
    nullable: true,
  })
  encryptedWriteKey!: string | null;

  @ApiProperty({ description: 'UUID of the root shared node' })
  rootNodeId!: string;

  @ApiProperty({ description: 'IPNS name of the root shared node' })
  shareRootIpnsName!: string;

  @ApiProperty({ description: 'Generation of the root node at invite creation (numeric string)' })
  rootGeneration!: string;

  @ApiProperty({
    description: 'Hex-encoded ECIES ciphertext of the display name, or null if not provided',
    type: String,
    nullable: true,
  })
  itemNameEncrypted!: string | null;
}

/**
 * Response for the claim invite endpoint.
 */
export class ClaimInviteResponseDto {
  @ApiProperty({ description: 'UUID of the created share' })
  shareId!: string;
}
