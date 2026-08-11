import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches, MaxLength } from 'class-validator';

/** Three dot-separated base64url segments; anything else is not a JWT. */
const COMPACT_JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const SIX_DIGITS = /^[0-9]{6}$/;

export class GoogleIdentityRequestDto {
  @ApiProperty({ description: 'The Google ID token collected by Google Identity Services' })
  @IsString()
  @MaxLength(4096)
  @Matches(COMPACT_JWT, { message: 'idToken must be a compact JWT' })
  idToken!: string;
}

export class EmailCodeRequestDto {
  @ApiProperty({ description: 'Address the verification code is sent to' })
  @IsEmail({}, { message: 'email must be an email address' })
  @MaxLength(254)
  email!: string;
}

export class EmailCodeVerifyRequestDto extends EmailCodeRequestDto {
  @ApiProperty({ description: 'The six-digit code CipherBox delivered' })
  @IsString()
  @Matches(SIX_DIGITS, { message: 'code must be six digits' })
  code!: string;
}

export class EmailCodeSentResponseDto {
  @ApiProperty()
  success!: boolean;
}

export class IdentityTokenResponseDto {
  @ApiProperty({ description: 'CipherBox identity token; the Core Kit logs in with it' })
  token!: string;

  @ApiProperty({
    description: 'The Core Kit verifierId this token is bound to — pass it to loginWithJWT',
  })
  verifierId!: string;

  @ApiProperty({
    description: 'The signed-in email, when the method carries one; null for wallet',
    nullable: true,
    type: String,
  })
  email!: string | null;

  @ApiProperty({ description: 'Token expiry, ISO 8601' })
  expiresAt!: string;
}

export class JwksResponseDto {
  @ApiProperty({
    description: 'The public half of the identity-token signing key, as JWKs',
    type: 'array',
    items: { type: 'object', additionalProperties: true },
  })
  keys!: Record<string, unknown>[];
}
