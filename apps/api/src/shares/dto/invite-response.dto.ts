import { ApiProperty } from '@nestjs/swagger';
import { InviteChildKeyDto } from './create-invite.dto';
import type { ChildKeyType } from '../types';

/**
 * Response for creating or listing invites (sharer's view).
 */
export class InviteResponseDto {
  @ApiProperty({ description: 'Invite UUID (for management operations like revoke)' })
  id!: string;

  @ApiProperty({ description: 'Invite token (URL-safe base64)' })
  token!: string;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty({ description: 'IPNS name of the shared item' })
  ipnsName!: string;

  @ApiProperty({ description: 'Display name of the shared item' })
  itemName!: string;

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
 * Returns the encrypted key ciphertext needed by the client to unwrap and re-wrap.
 */
export class InviteDataResponseDto {
  @ApiProperty({
    enum: ['active', 'expired', 'claimed', 'revoked'],
    description: 'Current status of the invite',
  })
  status!: string;

  @ApiProperty({
    description: 'Hex-encoded item key wrapped with ephemeral public key',
  })
  encryptedKey!: string;

  @ApiProperty({
    description: 'Array of child keys wrapped with ephemeral public key, or null',
    type: [InviteChildKeyDto],
    nullable: true,
  })
  encryptedChildKeys!: Array<{
    keyType: ChildKeyType;
    itemId: string;
    encryptedKey: string;
  }> | null;

  @ApiProperty({ enum: ['folder', 'file'] })
  itemType!: string;

  @ApiProperty({ description: 'IPNS name of the shared item' })
  ipnsName!: string;

  @ApiProperty({ description: 'Display name of the shared item' })
  itemName!: string;
}

/**
 * Response for the claim invite endpoint.
 */
export class ClaimInviteResponseDto {
  @ApiProperty({ description: 'UUID of the created share' })
  shareId!: string;
}
