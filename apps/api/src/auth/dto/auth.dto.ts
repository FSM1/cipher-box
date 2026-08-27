import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUUID, Matches, MaxLength } from 'class-validator';
import { HEX_32_BYTES_RE } from '../../common/patterns';
import { AUTH_METHOD_KINDS, type AuthMethodKind } from '../entities/auth-method.entity';

const HEX_PUBLIC_KEY = /^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$/;
const HEX_COMPACT_SIGNATURE = /^[0-9a-fA-F]{128}$/;
export const HEX_REFRESH_TOKEN = HEX_32_BYTES_RE;
const HEX_ETH_SIGNATURE = /^0x[0-9a-fA-F]{130}$/;

export class ChallengeRequestDto {
  @ApiProperty({
    description: 'secp256k1 identity publicKey, hex (compressed 33-byte or uncompressed 65-byte)',
    example: '02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc',
  })
  @IsString()
  @Matches(HEX_PUBLIC_KEY, { message: 'publicKey must be a hex secp256k1 public key' })
  publicKey!: string;
}

export class ChallengeResponseDto {
  @ApiProperty({ description: 'Server-issued challenge to sign with the identity key' })
  challenge!: string;

  @ApiProperty({ description: 'Challenge expiry, ISO 8601' })
  expiresAt!: string;
}

export class LoginRequestDto {
  @ApiProperty({ description: 'secp256k1 identity publicKey, hex' })
  @IsString()
  @Matches(HEX_PUBLIC_KEY, { message: 'publicKey must be a hex secp256k1 public key' })
  publicKey!: string;

  @ApiProperty({ description: 'The server-issued challenge, verbatim' })
  @IsString()
  @MaxLength(256)
  challenge!: string;

  @ApiProperty({
    description: 'Compact secp256k1 signature over sha256(challenge), 64 bytes hex',
  })
  @IsString()
  @Matches(HEX_COMPACT_SIGNATURE, { message: 'signature must be 64 bytes of hex' })
  signature!: string;
}

export class TokenResponseDto {
  @ApiProperty({ description: 'Short-lived access JWT' })
  accessToken!: string;

  @ApiProperty({
    description:
      'Rotating refresh token (also set as an HTTP-only cookie for web; desktop stores it in the OS keychain)',
  })
  refreshToken!: string;

  @ApiProperty({
    description:
      'Opaque read-scoped pseudonym for the read accelerator, rotating with the access token',
  })
  acceleratorToken!: string;

  @ApiPropertyOptional({ description: 'True when this login created the account implicitly' })
  isNewUser?: boolean;
}

export class SiweChallengeResponseDto {
  @ApiProperty({ description: 'Nonce to embed in the SIWE message' })
  nonce!: string;

  @ApiProperty({ description: 'Nonce expiry, ISO 8601' })
  expiresAt!: string;
}

export class SiweLoginRequestDto {
  @ApiProperty({ description: 'EIP-4361 message text' })
  @IsString()
  @MaxLength(4000)
  message!: string;

  @ApiProperty({ description: 'EIP-191 signature over the message, 0x-prefixed hex' })
  @IsString()
  @Matches(HEX_ETH_SIGNATURE, { message: 'signature must be a 65-byte 0x-prefixed hex string' })
  signature!: `0x${string}`;
}

export class AuthMethodDto {
  @ApiProperty({ description: 'Row id, the handle POST /auth/unlink takes', format: 'uuid' })
  id!: string;

  @ApiProperty({ description: 'How the method authenticates', enum: AUTH_METHOD_KINDS })
  kind!: AuthMethodKind;

  @ApiProperty({
    description: 'Truncated human-readable identifier; the stored hash never crosses',
    type: String,
    nullable: true,
    example: '02a1633c…51b5dc',
  })
  identifierDisplay!: string | null;

  @ApiProperty({ description: 'When the method was linked, ISO 8601' })
  createdAt!: string;

  @ApiProperty({
    description: 'Last login through this method, ISO 8601',
    type: String,
    nullable: true,
  })
  lastUsedAt!: string | null;
}

export class UnlinkMethodRequestDto {
  @ApiProperty({ description: 'The auth-method row to unlink', format: 'uuid' })
  @IsUUID()
  methodId!: string;

  @ApiProperty({ description: 'A fresh challenge from POST /auth/challenge, verbatim' })
  @IsString()
  @MaxLength(256)
  challenge!: string;

  @ApiProperty({
    description: 'Compact secp256k1 signature over sha256(challenge), 64 bytes hex',
  })
  @IsString()
  @Matches(HEX_COMPACT_SIGNATURE, { message: 'signature must be 64 bytes of hex' })
  signature!: string;
}

export class RefreshRequestDto {
  @ApiPropertyOptional({
    description: 'Refresh token; falls back to the refreshToken cookie when omitted',
  })
  @IsOptional()
  @IsString()
  @Matches(HEX_REFRESH_TOKEN, { message: 'refreshToken must be 32 bytes of lowercase hex' })
  refreshToken?: string;
}

export class LogoutResponseDto {
  @ApiProperty()
  success!: boolean;
}

export class TestLoginRequestDto {
  @ApiProperty({ description: 'Stable test-account handle (e.g. an email-shaped string)' })
  @IsString()
  @MaxLength(255)
  handle!: string;

  @ApiProperty({ description: 'Must match TEST_LOGIN_SECRET' })
  @IsString()
  @MaxLength(255)
  secret!: string;
}

export class TestLoginResponseDto extends TokenResponseDto {
  @ApiProperty({ description: 'Deterministic secp256k1 publicKey, compressed hex' })
  publicKey!: string;

  @ApiProperty({ description: 'Deterministic secp256k1 privateKey, hex (test hook only)' })
  privateKey!: string;
}
