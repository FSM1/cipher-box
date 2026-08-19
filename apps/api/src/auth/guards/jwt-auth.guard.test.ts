import { ExecutionContext, ForbiddenException, Type, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { beforeEach, describe, expect, it } from 'vitest';
import { DeviceApprovalController } from '../../device-approval/device-approval.controller';
import { DeviceController } from '../../device-approval/device.controller';
import { ALLOWED_SCOPES_KEY, type TokenScope } from '../decorators/allow-scope.decorator';
import { AuthenticatedRequest, JwtAuthGuard } from './jwt-auth.guard';

const SECRET = 'jwt-auth-guard-test-secret';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const PUBLIC_KEY = '03'.padEnd(66, 'a');

const jwt = new JwtService({ secret: SECRET });
const foreignJwt = new JwtService({ secret: 'a-different-secret' });

/** The routes a `device-approval` token is meant to reach, named literally. */
const ALLOWED_ROUTES: Array<[string, Type<unknown>, string]> = [
  ['DeviceApprovalController.create', DeviceApprovalController, 'create'],
  ['DeviceApprovalController.status', DeviceApprovalController, 'status'],
  ['DeviceApprovalController.cancel', DeviceApprovalController, 'cancel'],
];

const ROUTED_CONTROLLERS: Array<Type<unknown>> = [DeviceApprovalController, DeviceController];

function methodsOf(controller: Type<unknown>): string[] {
  return Object.getOwnPropertyNames(controller.prototype).filter((name) => name !== 'constructor');
}

function contextFor(
  controller: Type<unknown>,
  method: string,
  headers: Record<string, string> = {}
): { context: ExecutionContext; request: AuthenticatedRequest } {
  const request = { headers } as unknown as AuthenticatedRequest;
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => (controller.prototype as Record<string, unknown>)[method],
    getClass: () => controller,
  } as unknown as ExecutionContext;
  return { context, request };
}

async function bearer(claims: Record<string, unknown>, signer = jwt): Promise<string> {
  return `Bearer ${await signer.signAsync(claims, { expiresIn: 900 })}`;
}

describe('JwtAuthGuard authentication', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    guard = new JwtAuthGuard(jwt, new Reflector());
  });

  it('refuses a request with no Authorization header', async () => {
    const { context } = contextFor(DeviceController, 'list');
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a non-Bearer Authorization header', async () => {
    const { context } = contextFor(DeviceController, 'list', { authorization: 'Basic abc' });
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a token signed with a different secret', async () => {
    const { context } = contextFor(DeviceController, 'list', {
      authorization: await bearer({ sub: USER_ID, publicKey: PUBLIC_KEY }, foreignJwt),
    });
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('refuses an expired token', async () => {
    const expired = await jwt.signAsync(
      { sub: USER_ID, publicKey: PUBLIC_KEY },
      { expiresIn: -10 }
    );
    const { context } = contextFor(DeviceController, 'list', {
      authorization: `Bearer ${expired}`,
    });
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });
});

describe('JwtAuthGuard unscoped tokens carry full account authority', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    guard = new JwtAuthGuard(jwt, new Reflector());
  });

  it('populates request.user with no scope on an undecorated route', async () => {
    const { context, request } = contextFor(DeviceApprovalController, 'respond', {
      authorization: await bearer({ sub: USER_ID, publicKey: PUBLIC_KEY }),
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user).toEqual({ userId: USER_ID, publicKey: PUBLIC_KEY, scope: undefined });
    expect(request.user.scope).toBeUndefined();
  });

  it('is allowed on a scope-marked route too', async () => {
    const { context, request } = contextFor(DeviceApprovalController, 'create', {
      authorization: await bearer({ sub: USER_ID, publicKey: PUBLIC_KEY }),
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.user.userId).toBe(USER_ID);
    expect(request.user.scope).toBeUndefined();
  });

  it('reaches every routed handler on both controllers', async () => {
    for (const controller of ROUTED_CONTROLLERS) {
      for (const method of methodsOf(controller)) {
        const { context } = contextFor(controller, method, {
          authorization: await bearer({ sub: USER_ID, publicKey: PUBLIC_KEY }),
        });
        await expect(guard.canActivate(context)).resolves.toBe(true);
      }
    }
  });
});

describe('JwtAuthGuard scoped tokens are a capability, not a session', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    guard = new JwtAuthGuard(jwt, new Reflector());
  });

  const scopedHeader = (scope: string): Promise<string> =>
    bearer({ sub: USER_ID, publicKey: PUBLIC_KEY, scope });

  it.each(ALLOWED_ROUTES)(
    'admits a device-approval token on %s and records the scope',
    async (_label, controller, method) => {
      const { context, request } = contextFor(controller, method, {
        authorization: await scopedHeader('device-approval'),
      });

      await expect(guard.canActivate(context)).resolves.toBe(true);
      expect(request.user).toEqual({
        userId: USER_ID,
        publicKey: PUBLIC_KEY,
        scope: 'device-approval',
      });
    }
  );

  const refusedRoutes: Array<[string, Type<unknown>, string]> = [
    ['DeviceApprovalController.pending', DeviceApprovalController, 'pending'],
    ['DeviceApprovalController.respond', DeviceApprovalController, 'respond'],
    ['DeviceController.register', DeviceController, 'register'],
    ['DeviceController.list', DeviceController, 'list'],
    ['DeviceController.revoke', DeviceController, 'revoke'],
  ];

  it.each(refusedRoutes)(
    'refuses a device-approval token on %s — a scoped token reaches the requester routes and no others',
    async (_label, controller, method) => {
      const { context, request } = contextFor(controller, method, {
        authorization: await scopedHeader('device-approval'),
      });

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
      expect(request.user).toBeUndefined();
    }
  );

  it.each(ALLOWED_ROUTES)(
    'refuses an unknown scope even on %s',
    async (_label, controller, method) => {
      const { context } = contextFor(controller, method, {
        authorization: await scopedHeader('some-scope-we-never-issued'),
      });

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
    }
  );
});

/**
 * Deny by default is structural, not a hand-kept list: a route added without
 * `@AllowScope` must fail this suite rather than silently admit a scoped token.
 */
describe('JwtAuthGuard deny-by-default over the real route metadata', () => {
  const reflector = new Reflector();
  const guard = new JwtAuthGuard(jwt, reflector);

  function declaredScopes(controller: Type<unknown>, method: string): TokenScope[] | undefined {
    const { context } = contextFor(controller, method);
    return reflector.getAllAndOverride<TokenScope[] | undefined>(ALLOWED_SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
  }

  it('marks exactly the rendezvous requester routes with @AllowScope', () => {
    const decorated = ROUTED_CONTROLLERS.flatMap((controller) =>
      methodsOf(controller)
        .filter((method) => declaredScopes(controller, method)?.includes('device-approval'))
        .map((method) => `${controller.name}.${method}`)
    );
    expect(decorated).toEqual(ALLOWED_ROUTES.map(([label]) => label));
  });

  it('admits a scoped token only where the metadata names its scope', async () => {
    for (const controller of ROUTED_CONTROLLERS) {
      for (const method of methodsOf(controller)) {
        const { context } = contextFor(controller, method, {
          authorization: await bearer({
            sub: USER_ID,
            publicKey: PUBLIC_KEY,
            scope: 'device-approval',
          }),
        });
        const admitted = declaredScopes(controller, method)?.includes('device-approval') ?? false;

        if (admitted) {
          await expect(guard.canActivate(context)).resolves.toBe(true);
        } else {
          await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
        }
      }
    }
  });
});
