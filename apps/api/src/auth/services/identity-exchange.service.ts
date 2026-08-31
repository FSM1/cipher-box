import { Injectable, UnauthorizedException } from '@nestjs/common';
import { parseSiweMessage } from 'viem/siwe';
import type { IdentitySubjectKind } from '../entities/identity-subject.entity';
import { ChallengeService } from './challenge.service';
import { EmailOtpService } from './email-otp.service';
import { GoogleOAuthService } from './google-oauth.service';
import { IdentitySubjectService } from './identity-subject.service';
import { IdentityTokenService } from './identity-token.service';
import { SIWE_LOGIN_STATEMENT, SiweService } from './siwe.service';

export interface IdentityGrant {
  /** The CipherBox identity token the Core Kit logs in with. */
  token: string;
  /** The Core Kit `verifierId` this token's `sub` names. */
  verifierId: string;
  /** The signed-in address, when the method carries one; for display only. */
  email: string | null;
  expiresAt: Date;
}

/**
 * Turns a verified provider credential into a CipherBox identity token
 * (ADR 0008 D1/D2). Every method lands on the same mint, so all three reach the
 * same derived key for the same provider identity.
 *
 * No account is created here. `POST /auth/login` still owns that, keyed by the
 * identity key the Core Kit has not derived yet at this point in the flow.
 */
@Injectable()
export class IdentityExchangeService {
  constructor(
    private readonly google: GoogleOAuthService,
    private readonly emailOtp: EmailOtpService,
    private readonly siwe: SiweService,
    private readonly challenges: ChallengeService,
    private readonly subjects: IdentitySubjectService,
    private readonly tokens: IdentityTokenService
  ) {}

  async fromGoogleToken(idToken: string): Promise<IdentityGrant> {
    const identity = await this.google.verify(idToken);
    return this.mint('google', identity.subject, truncateEmail(identity.email), identity.email);
  }

  sendEmailCode(email: string): Promise<void> {
    return this.emailOtp.send(email);
  }

  async fromEmailCode(email: string, code: string): Promise<IdentityGrant> {
    const address = this.emailOtp.verify(email, code);
    return this.mint('email', address, truncateEmail(address), address);
  }

  async fromWalletSignature(message: string, signature: `0x${string}`): Promise<IdentityGrant> {
    const nonce = parseSiweMessage(message).nonce;
    if (!nonce) {
      throw new UnauthorizedException('Invalid SIWE message: missing nonce');
    }
    this.challenges.consume(nonce, 'siwe-login');
    const address = await this.siwe.verifySiweMessage(
      message,
      signature,
      nonce,
      SIWE_LOGIN_STATEMENT
    );
    return this.mint('wallet', address, this.siwe.truncateWalletAddress(address), null);
  }

  private async mint(
    method: IdentitySubjectKind,
    identifier: string,
    identifierDisplay: string,
    email: string | null
  ): Promise<IdentityGrant> {
    const verifierId = await this.subjects.resolve(method, identifier, identifierDisplay);
    const { token, expiresAt } = await this.tokens.sign({ subject: verifierId, method });
    return { token, verifierId, email, expiresAt };
  }
}

/** Truncated address for display, e.g. "al***@example.com". */
function truncateEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  return `${local.slice(0, 2)}***@${domain}`;
}
