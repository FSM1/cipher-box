import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Matches, MaxLength, ValidateIf } from 'class-validator';
import { CANONICAL_BASE64_RE } from '../../common/patterns';
import {
  DEVICE_PUBLIC_KEY_HEX,
  DEVICE_SIGNATURE_HEX,
  type ApprovalDecision,
} from '../device-signature';
import type { DeviceApprovalStatus } from '../entities/device-approval.entity';

/** Compressed secp256k1, lowercase hex — the shape the requester's ephemeral key takes. */
const EPHEMERAL_PUBLIC_KEY_HEX = /^(02|03)[0-9a-f]{64}$/;

/**
 * A base64 string longer than this cannot decode to <= 1 KiB, so the DTO rejects
 * it cheaply; the service still enforces the exact decoded-byte bound.
 */
const MAX_SEALED_FACTOR_BASE64_LENGTH = 1500;

const DEVICE_PUBLIC_KEY_MESSAGE = 'must be a 64-character lowercase-hex Ed25519 public key';
const SIGNATURE_MESSAGE = 'must be a 128-character lowercase-hex Ed25519 signature';

export class RegisterDeviceDto {
  @ApiProperty({ description: 'Raw Ed25519 device identity public key, lowercase hex' })
  @IsString()
  @Matches(DEVICE_PUBLIC_KEY_HEX, { message: `publicKey ${DEVICE_PUBLIC_KEY_MESSAGE}` })
  publicKey!: string;

  @ApiProperty({
    description:
      'Ed25519 signature proving possession, over `cipherbox/device-registration/v1`, the ' +
      'authenticated account id, and this publicKey, newline-joined',
  })
  @IsString()
  @Matches(DEVICE_SIGNATURE_HEX, { message: `signature ${SIGNATURE_MESSAGE}` })
  signature!: string;

  @ApiProperty({
    description:
      'CipherBox identity token this device signed in with; binds the account to the identity ' +
      'a pre-reconstruction device can present',
  })
  @IsString()
  @MaxLength(4096)
  identityToken!: string;

  @ApiPropertyOptional({
    description: 'Display label for the approval prompt; context, not evidence',
  })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  label?: string;
}

export class RegisteredDeviceDto {
  @ApiProperty()
  id!: string;

  @ApiProperty({ description: 'Raw Ed25519 device identity public key, lowercase hex' })
  publicKey!: string;

  @ApiProperty({ nullable: true, type: String })
  label!: string | null;

  @ApiProperty({ description: 'ISO 8601' })
  createdAt!: string;

  @ApiProperty({ description: 'ISO 8601' })
  lastSeenAt!: string;
}

export class RegisteredDeviceListDto {
  @ApiProperty({ type: [RegisteredDeviceDto] })
  devices!: RegisteredDeviceDto[];
}

export class DeviceApprovalSessionDto {
  @ApiProperty({ description: 'A CipherBox identity token for the account being reached' })
  @IsString()
  @MaxLength(4096)
  identityToken!: string;
}

export class DeviceApprovalSessionResponseDto {
  @ApiProperty({
    description: 'Scoped, non-refreshable access token; reaches the device-approval routes only',
  })
  accessToken!: string;

  @ApiProperty({ description: 'Token lifetime in seconds' })
  expiresIn!: number;
}

export class CreateApprovalDto {
  @ApiProperty({ description: 'The requesting device identity public key, lowercase hex' })
  @IsString()
  @Matches(DEVICE_PUBLIC_KEY_HEX, { message: `devicePublicKey ${DEVICE_PUBLIC_KEY_MESSAGE}` })
  devicePublicKey!: string;

  @ApiProperty({
    description: 'Compressed secp256k1 key the factor must be sealed to, lowercase hex',
  })
  @IsString()
  @Matches(EPHEMERAL_PUBLIC_KEY_HEX, {
    message: 'ephemeralPublicKey must be a 66-character lowercase-hex compressed secp256k1 key',
  })
  ephemeralPublicKey!: string;

  @ApiProperty({
    description:
      'Ed25519 signature over `cipherbox/device-approval/request/v1`, devicePublicKey and ' +
      'ephemeralPublicKey, newline-joined',
  })
  @IsString()
  @Matches(DEVICE_SIGNATURE_HEX, { message: `signature ${SIGNATURE_MESSAGE}` })
  signature!: string;
}

export class CreateApprovalResponseDto {
  @ApiProperty()
  requestId!: string;

  @ApiProperty({ description: 'ISO 8601; the row is gone at this instant' })
  expiresAt!: string;
}

export class PendingApprovalDto {
  @ApiProperty()
  requestId!: string;

  @ApiProperty({ description: 'The requesting device identity public key, lowercase hex' })
  requesterDevicePublicKey!: string;

  @ApiProperty({ description: 'Seal to THIS key, once its comparison value matches (ADR 0009 D3)' })
  ephemeralPublicKey!: string;

  @ApiProperty({
    description:
      'The requester signature over the pair above; re-check it before sealing so a ' +
      'substituted ephemeral key is caught without trusting this response',
  })
  requestSignature!: string;

  @ApiProperty({ description: 'ISO 8601' })
  createdAt!: string;

  @ApiProperty({ description: 'ISO 8601' })
  expiresAt!: string;
}

export class PendingApprovalListDto {
  @ApiProperty({ type: [PendingApprovalDto] })
  requests!: PendingApprovalDto[];
}

export class RespondApprovalDto {
  @ApiProperty({ enum: ['approve', 'deny'] })
  @IsIn(['approve', 'deny'])
  decision!: ApprovalDecision;

  @ApiProperty({ description: 'The approving device identity public key; must be registered' })
  @IsString()
  @Matches(DEVICE_PUBLIC_KEY_HEX, { message: `devicePublicKey ${DEVICE_PUBLIC_KEY_MESSAGE}` })
  devicePublicKey!: string;

  @ApiProperty({
    description:
      'Ed25519 signature over `cipherbox/device-approval/response/v1`, devicePublicKey, the ' +
      'request id, the decision, the ephemeral key and sealedFactor, newline-joined',
  })
  @IsString()
  @Matches(DEVICE_SIGNATURE_HEX, { message: `signature ${SIGNATURE_MESSAGE}` })
  signature!: string;

  @ApiPropertyOptional({
    description:
      'Opaque ciphertext sealed to the request ephemeral key, base64 (decodes to <= 1 KiB). ' +
      'Required to approve, refused on a denial. Never inspected server-side.',
  })
  @ValidateIf((dto: RespondApprovalDto) => dto.decision === 'approve')
  @IsString()
  @MaxLength(MAX_SEALED_FACTOR_BASE64_LENGTH)
  @Matches(CANONICAL_BASE64_RE, { message: 'sealedFactor must be canonically padded base64' })
  sealedFactor?: string;
}

export class ApprovalStatusDto {
  @ApiProperty({ enum: ['pending', 'approved', 'denied'] })
  status!: DeviceApprovalStatus;

  @ApiProperty({ description: 'The ephemeral key this rendezvous was opened for' })
  ephemeralPublicKey!: string;

  @ApiProperty({ description: 'ISO 8601' })
  expiresAt!: string;

  @ApiPropertyOptional({
    type: String,
    description:
      'Sealed factor, base64; present once approved, and the row is gone after this read',
  })
  sealedFactor?: string;

  @ApiPropertyOptional({ type: String, description: 'The approving device identity public key' })
  responderDevicePublicKey?: string;

  @ApiPropertyOptional({
    type: String,
    description: 'The approver signature over the decision, the ephemeral key and sealedFactor',
  })
  responseSignature?: string;
}

export class ApprovalActionResponseDto {
  @ApiProperty()
  success!: boolean;
}
