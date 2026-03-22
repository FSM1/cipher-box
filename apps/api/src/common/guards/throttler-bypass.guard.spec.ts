import { ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { BypassableThrottlerGuard } from './throttler-bypass.guard';

// Mock ThrottlerGuard.canActivate so we can track when the parent is called
const superCanActivate = jest.fn().mockResolvedValue(true);
jest.spyOn(ThrottlerGuard.prototype, 'canActivate').mockImplementation(superCanActivate);

function createMockContext(headers: Record<string, string | string[]> = {}): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ headers }),
      getResponse: () => ({}),
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

describe('BypassableThrottlerGuard', () => {
  let guard: BypassableThrottlerGuard;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    guard = Object.create(BypassableThrottlerGuard.prototype);
    superCanActivate.mockClear();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should bypass when secret matches and NODE_ENV is not production', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'test-secret';
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({ 'x-throttle-bypass': 'test-secret' });
    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(superCanActivate).not.toHaveBeenCalled();
  });

  it('should fall through to parent when secret does not match', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'test-secret';
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({ 'x-throttle-bypass': 'wrong-secret' });
    await guard.canActivate(ctx);

    expect(superCanActivate).toHaveBeenCalledWith(ctx);
  });

  it('should fall through to parent when header is missing', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'test-secret';
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({});
    await guard.canActivate(ctx);

    expect(superCanActivate).toHaveBeenCalledWith(ctx);
  });

  it('should fall through to parent in production even with valid header', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'test-secret';
    process.env.NODE_ENV = 'production';

    const ctx = createMockContext({ 'x-throttle-bypass': 'test-secret' });
    await guard.canActivate(ctx);

    expect(superCanActivate).toHaveBeenCalledWith(ctx);
  });

  it('should fall through to parent when THROTTLE_BYPASS_SECRET is not set', async () => {
    delete process.env.THROTTLE_BYPASS_SECRET;
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({ 'x-throttle-bypass': 'anything' });
    await guard.canActivate(ctx);

    expect(superCanActivate).toHaveBeenCalledWith(ctx);
  });

  it('should handle array header values (first element)', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'test-secret';
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({ 'x-throttle-bypass': ['test-secret', 'other'] });
    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(superCanActivate).not.toHaveBeenCalled();
  });

  it('should reject when secret lengths differ (timing-safe)', async () => {
    process.env.THROTTLE_BYPASS_SECRET = 'short';
    process.env.NODE_ENV = 'test';

    const ctx = createMockContext({ 'x-throttle-bypass': 'a-much-longer-secret' });
    await guard.canActivate(ctx);

    expect(superCanActivate).toHaveBeenCalledWith(ctx);
  });
});
