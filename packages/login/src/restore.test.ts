import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createLoginFlow, resetLoginFlowLatches } from './flow';
import {
  fakeAccount,
  fakeExchange,
  fakeFacade,
  fakeProgress,
  fakeSession,
  passThroughCollector,
} from './testFakes';

const REFUSAL = new Error('master poly commits inconsistent with tssPubKey');

beforeEach(() => {
  resetLoginFlowLatches();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function restored(facade = fakeFacade(), session = fakeSession({ loggedIn: true })) {
  const progress = fakeProgress();
  const account = fakeAccount();
  const exportSecret = vi.spyOn(session.session, '_UNSAFE_exportTssKey');
  const flow = createLoginFlow({
    session: session.session,
    facade: facade.facade,
    exchange: fakeExchange().exchange,
    collector: passThroughCollector(),
    secrets: null,
    account: account.account,
    progress: progress.progress,
    now: () => new Date(),
  });
  return { flow, session, facade, progress, account, exportSecret };
}

it('restores the same saved session after a transient export refusal without signing in again', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);

  const done = p.flow.resume();
  await vi.runAllTimersAsync();
  await done;

  expect(p.exportSecret).toHaveBeenCalledTimes(2);
  expect(p.session.calls.logins).toEqual([]);
  expect(p.session.calls.logouts).toBe(0);
  expect(p.facade.calls.secrets).toHaveLength(1);
  expect(p.progress.failures).toEqual([]);
  expect(p.account.calls.signedIn).toHaveLength(1);
});

it('keeps simultaneous restore consumers on one delayed attempt', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);
  const first = p.flow.resume();
  const second = p.flow.resume();
  expect(second).toBe(first);

  await vi.advanceTimersByTimeAsync(14_999);
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.session.calls.logouts).toBe(0);
  expect(p.facade.calls.secrets).toEqual([]);

  await vi.runAllTimersAsync();
  await Promise.all([first, second]);
  expect(p.exportSecret).toHaveBeenCalledTimes(2);
  expect(p.facade.calls.secrets).toHaveLength(1);
});

it.each([0, 0.5, 0.9999])(
  'ends a persistent refusal within the retry window with jitter %s',
  async (jitter) => {
    vi.spyOn(Math, 'random').mockReturnValue(jitter);
    const p = restored();
    p.exportSecret.mockRejectedValue(REFUSAL);
    const started = Date.now();
    const done = p.flow.resume();
    await vi.runAllTimersAsync();
    await done;

    expect(Date.now() - started).toBeLessThan(120_000);
    expect(p.exportSecret.mock.calls.length).toBeGreaterThan(2);
    expect(p.session.calls.logouts).toBe(1);
    expect(p.progress.failures).toEqual([REFUSAL]);
    expect(p.facade.calls.secrets).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  }
);

it('charges time inside the SDK against the retry window', async () => {
  const p = restored();
  p.exportSecret.mockImplementation(async () => {
    await new Promise((resolve) => setTimeout(resolve, 110_000));
    throw REFUSAL;
  });
  const done = p.flow.resume();
  await vi.runAllTimersAsync();
  await done;
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.session.calls.logouts).toBe(1);
});

it('does not restart after a suspended page wakes past the retry deadline', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValue(REFUSAL);
  const done = p.flow.resume();
  await vi.advanceTimersByTimeAsync(1);
  vi.setSystemTime(Date.now() + 180_000);
  await vi.runAllTimersAsync();
  await done;
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
});

it.each([
  new Error('all auth network nodes are currently busy, please try again'),
  { url: 'https://node-1.dev-node.web3auth.io/rss?token=private', status: 503 },
])('recovers from a recognized provider refusal', async (failure) => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(failure);
  const done = p.flow.resume();
  await vi.runAllTimersAsync();
  await done;
  expect(p.facade.calls.secrets).toHaveLength(1);
  expect(p.session.calls.logouts).toBe(0);
});

it.each([
  new Error('invalid factor'),
  new Error('signature expired'),
  new Error('trust violation'),
  { url: 'https://node-1.dev-node.web3auth.io/rss', status: 401 },
  { url: 'https://api.example.test/login', status: 503 },
  { url: 'https://web3auth.io.attacker.test/rss', status: 503 },
  { url: 'http://node-1.dev-node.web3auth.io/rss', status: 503 },
  { url: 'not a URL', status: 503 },
])('fails closed on an unrecognized or expired export refusal', async (failure) => {
  const p = restored();
  p.exportSecret.mockRejectedValue(failure);
  await p.flow.resume();
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.session.calls.logouts).toBe(1);
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.progress.failures).toEqual([failure]);
  expect(vi.getTimerCount()).toBe(0);
});

it('does not retry an engine failure even if its message matches a provider refusal', async () => {
  const p = restored(fakeFacade({ start: () => Promise.reject(REFUSAL) }));
  await p.flow.resume();
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.facade.calls.secrets).toHaveLength(1);
  expect(p.session.calls.logouts).toBe(1);
  expect(vi.getTimerCount()).toBe(0);
});

it('does not retry malformed key material', async () => {
  const p = restored();
  p.exportSecret.mockResolvedValue('not-hex');
  await p.flow.resume();
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.session.calls.logouts).toBe(1);
  expect(vi.getTimerCount()).toBe(0);
});

it('stops when the saved session expires during the delay', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);
  const done = p.flow.resume();
  await vi.advanceTimersByTimeAsync(1);
  p.session.session.isLoggedIn = () => false;
  await vi.runAllTimersAsync();
  await done;
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.session.calls.logouts).toBe(1);
});

it('cancels a pending retry when logout retires the session', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);
  const done = p.flow.resume();
  await vi.advanceTimersByTimeAsync(1);
  await expect(p.flow.logout()).rejects.toThrow('another sign-in is already in progress');
  await done;
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.session.calls.logouts).toBe(1);
  expect(vi.getTimerCount()).toBe(0);
});

it('never hands a late export to the engine after logout', async () => {
  const p = restored();
  let finish!: (secret: string) => void;
  p.exportSecret.mockReturnValueOnce(new Promise((resolve) => (finish = resolve)));
  const done = p.flow.resume();
  await expect(p.flow.logout()).rejects.toThrow('another sign-in is already in progress');
  finish('0f'.repeat(32));
  await done;
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.session.calls.logouts).toBe(1);
});

it('checks cancellation again at the transfer after the export has already settled', async () => {
  const p = restored();
  let finish!: (secret: string) => void;
  p.exportSecret.mockReturnValueOnce(new Promise((resolve) => (finish = resolve)));
  const done = p.flow.resume();
  finish('0f'.repeat(32));
  await Promise.resolve();
  expect(p.facade.calls.secrets).toEqual([]);
  await expect(p.flow.logout()).rejects.toThrow('another sign-in is already in progress');
  await done;
  expect(p.facade.calls.secrets).toEqual([]);
  expect(p.session.calls.logouts).toBe(1);
});

it('cancels the active restoration even after a replacement facade asked to resume', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);
  const done = p.flow.resume();
  await vi.advanceTimersByTimeAsync(1);
  const replacement = restored(fakeFacade(), p.session);
  await replacement.flow.resume();
  await expect(replacement.flow.logout()).rejects.toThrow('another sign-in is already in progress');
  await vi.runAllTimersAsync();
  await done;
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(p.facade.calls.secrets).toEqual([]);
  expect(replacement.facade.calls.secrets).toEqual([]);
});

it('leaves deliberate sign-in failures to their existing caller', async () => {
  const p = restored();
  p.exportSecret.mockRejectedValueOnce(REFUSAL);
  await expect(p.flow.loginWithGoogle('token')).rejects.toBe(REFUSAL);
  expect(p.exportSecret).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
});
