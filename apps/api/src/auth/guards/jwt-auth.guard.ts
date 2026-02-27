import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Standard JWT validation (sets req.user via JwtStrategy.validate)
    const result = await super.canActivate(context);
    if (!result) return false;

    // Check scope restrictions on the authenticated token
    const request = context.switchToHttp().getRequest();
    const scope = request.user?.scope as string[] | undefined;

    // No scope = full access token, allow everything
    if (!scope || scope.length === 0) return true;

    // Scoped token: check if route allows this scope via @AllowScope()
    const allowedScopes = this.reflector.getAllAndOverride<string[]>('allowedScopes', [
      context.getHandler(),
      context.getClass(),
    ]);

    // Route not decorated with @AllowScope → deny scoped tokens
    if (!allowedScopes) {
      throw new ForbiddenException('Insufficient token scope');
    }

    // Check if token scope intersects with allowed scopes
    if (!scope.some((s) => allowedScopes.includes(s))) {
      throw new ForbiddenException('Insufficient token scope');
    }

    return true;
  }
}
