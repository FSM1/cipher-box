import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';

export interface AuthenticatedUser {
  userId: string;
  publicKey: string;
}

export type AuthenticatedRequest = Request & { user: AuthenticatedUser };

/** Verifies the short-lived access JWT from the Authorization header. */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = request.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing access token');
    }
    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string; publicKey: string }>(
        header.slice('Bearer '.length)
      );
      request.user = { userId: payload.sub, publicKey: payload.publicKey };
      return true;
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
