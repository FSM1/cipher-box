import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { ALLOWED_SCOPES_KEY, type TokenScope } from '../decorators/allow-scope.decorator';

export interface AuthenticatedUser {
  userId: string;
  /** The account pseudonym a FULL session proves; a scoped token carries none. */
  publicKey?: string;
  /** Present only on a restricted token; absent means full account authority. */
  scope?: TokenScope;
}

export type AuthenticatedRequest = Request & { user: AuthenticatedUser };

/**
 * The caller's account pseudonym, for routes that address by it. Only a full
 * session carries one, and a scoped token never reaches such a route, so the
 * refusal here is a fail-closed backstop rather than a reachable answer.
 */
export function accountPublicKey(request: AuthenticatedRequest): string {
  const { publicKey } = request.user;
  if (!publicKey) {
    throw new UnauthorizedException('This token does not identify an account key');
  }
  return publicKey;
}

interface AccessTokenClaims {
  sub: string;
  publicKey: string;
  scope?: string;
}

/** Verifies the short-lived access JWT from the Authorization header. */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = request.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing access token');
    }
    let payload: AccessTokenClaims;
    try {
      payload = await this.jwtService.verifyAsync<AccessTokenClaims>(
        header.slice('Bearer '.length)
      );
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }
    const scope = payload.scope as TokenScope | undefined;
    if (scope !== undefined) {
      this.assertScopeReaches(context, scope);
    }
    request.user = { userId: payload.sub, publicKey: payload.publicKey, scope };
    return true;
  }

  /** A handler-level `@AllowScope` overrides its controller's. */
  private assertScopeReaches(context: ExecutionContext, scope: TokenScope): void {
    const allowed = this.reflector.getAllAndOverride<TokenScope[] | undefined>(ALLOWED_SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!allowed?.includes(scope)) {
      throw new ForbiddenException('Insufficient token scope');
    }
  }
}
