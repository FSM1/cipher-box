import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { of, Observable } from 'rxjs';

// We need to mock AuthGuard from @nestjs/passport so our guard doesn't
// actually try to perform passport authentication.
// The mock provides a controllable super.canActivate().
let superCanActivateResult: boolean | Promise<boolean> | Observable<boolean> = true;

jest.mock('@nestjs/passport', () => {
  return {
    AuthGuard: () => {
      class MockAuthGuard {
        canActivate() {
          return superCanActivateResult;
        }
      }
      return MockAuthGuard;
    },
  };
});

// Re-import after mocking to get the mocked version
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { JwtAuthGuard: MockedJwtAuthGuard } = require('./jwt-auth.guard');

describe('JwtAuthGuard', () => {
  let guard: InstanceType<typeof MockedJwtAuthGuard>;
  let reflector: jest.Mocked<Reflector>;

  const createMockContext = (user?: Record<string, unknown>): ExecutionContext => {
    const request = { user };
    return {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
        getNext: () => jest.fn(),
      }),
      getHandler: () => jest.fn(),
      getClass: () => jest.fn(),
      getArgs: () => [],
      getArgByIndex: () => undefined,
      switchToRpc: () => ({}) as unknown,
      switchToWs: () => ({}) as unknown,
      getType: () => 'http' as const,
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = {
      getAllAndOverride: jest.fn(),
      get: jest.fn(),
      getAll: jest.fn(),
      getAllAndMerge: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    guard = new MockedJwtAuthGuard(reflector);
    superCanActivateResult = true;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('canActivate', () => {
    it('should return false when super.canActivate returns false', async () => {
      superCanActivateResult = false;
      const context = createMockContext();

      const result = await guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should return false when super.canActivate returns Promise<false>', async () => {
      superCanActivateResult = Promise.resolve(false);
      const context = createMockContext();

      const result = await guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should handle Observable return from super.canActivate', async () => {
      superCanActivateResult = of(true);
      const context = createMockContext({ id: 'user-1' });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return true for full access token (no scope)', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1' });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return true for full access token (undefined scope)', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1', scope: undefined });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return true for full access token (empty scope array)', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1', scope: [] });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should throw ForbiddenException when scoped token hits route without @AllowScope', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1', scope: ['device-approval'] });
      reflector.getAllAndOverride.mockReturnValue(undefined);

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
      await expect(guard.canActivate(context)).rejects.toThrow('Insufficient token scope');
    });

    it('should throw ForbiddenException when token scope does not intersect allowed scopes', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1', scope: ['device-approval'] });
      reflector.getAllAndOverride.mockReturnValue(['admin', 'migration']);

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
    });

    it('should return true when token scope intersects with allowed scopes', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1', scope: ['device-approval'] });
      reflector.getAllAndOverride.mockReturnValue(['device-approval', 'migration']);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return true when any token scope matches any allowed scope', async () => {
      superCanActivateResult = true;
      const context = createMockContext({
        id: 'user-1',
        scope: ['scope-a', 'scope-b', 'device-approval'],
      });
      reflector.getAllAndOverride.mockReturnValue(['device-approval']);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should check reflector with handler and class from context', async () => {
      superCanActivateResult = true;
      const handler = jest.fn();
      const cls = jest.fn();
      const context = {
        switchToHttp: () => ({
          getRequest: () => ({ user: { id: 'user-1', scope: ['test'] } }),
        }),
        getHandler: () => handler,
        getClass: () => cls,
      } as unknown as ExecutionContext;
      reflector.getAllAndOverride.mockReturnValue(['test']);

      await guard.canActivate(context);

      expect(reflector.getAllAndOverride).toHaveBeenCalledWith('allowedScopes', [handler, cls]);
    });

    it('should handle user object without scope property', async () => {
      superCanActivateResult = true;
      const context = createMockContext({ id: 'user-1' });

      const result = await guard.canActivate(context);

      // No scope = full access
      expect(result).toBe(true);
    });
  });
});
