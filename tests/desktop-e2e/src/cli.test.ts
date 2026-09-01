import { describe, expect, it } from 'vitest';
import { names, parseArguments, select, withDeadline } from './cli';

describe('parseArguments', () => {
  it('runs every scenario when nothing is named', () => {
    expect(parseArguments([])).toEqual({ help: false, list: false, only: [] });
  });

  it('collects a repeated scenario name', () => {
    expect(parseArguments(['--scenario', 'one', '--scenario', 'two']).only).toEqual(['one', 'two']);
  });

  it('takes both spellings of help', () => {
    expect(parseArguments(['-h']).help).toBe(true);
    expect(parseArguments(['--help']).help).toBe(true);
  });

  it('refuses a scenario flag that names nothing', () => {
    expect(() => parseArguments(['--scenario'])).toThrow(/needs a scenario name/);
    expect(() => parseArguments(['--scenario', '--list'])).toThrow(/needs a scenario name/);
  });

  it('refuses an argument it does not serve', () => {
    expect(() => parseArguments(['--only', 'one'])).toThrow(/unknown argument --only/);
  });
});

describe('select', () => {
  const scenarios = [{ name: 'first' }, { name: 'second' }, { name: 'third' }];
  const every = { help: false, list: false, only: [] };

  it('takes every scenario in run order when the options name none', () => {
    expect(select(scenarios, every)).toEqual(scenarios);
  });

  it('takes the named scenarios in the order they are named', () => {
    expect(names(select(scenarios, { ...every, only: ['third', 'first'] }))).toEqual([
      'third',
      'first',
    ]);
  });

  it('refuses a name no scenario carries, and lists the names it has', () => {
    expect(() => select(scenarios, { ...every, only: ['fourth'] })).toThrow(
      'no scenario is named fourth. The names are: first, second, third'
    );
  });
});

describe('withDeadline', () => {
  it('takes the body value and releases nothing when the body wins', async () => {
    let released = false;
    const value = await withDeadline(Promise.resolve('done'), 50, 'the body', async () => {
      released = true;
    });
    expect(value).toBe('done');
    expect(released).toBe(false);
  });

  it('releases what the body holds before the deadline rejects', async () => {
    const order: string[] = [];
    const expiry = withDeadline(new Promise(() => {}), 5, 'the scenario', async () => {
      order.push('released');
    });
    await expect(expiry).rejects.toThrow('the scenario did not finish within 5ms');
    order.push('rejected');
    expect(order).toEqual(['released', 'rejected']);
  });

  it('keeps the deadline authoritative when the body lands during the release', async () => {
    let finishRelease = (): void => {};
    const released = new Promise<void>((resolve) => {
      finishRelease = resolve;
    });
    let finishBody = (): void => {};
    const body = new Promise<string>((resolve) => {
      finishBody = () => resolve('late');
    });

    const raced = withDeadline(body, 5, 'the scenario', () => released);
    // The timer has fired and the release is still running. A body that lands
    // now must not win the race and hand the caller its teardown.
    await new Promise((resolve) => setTimeout(resolve, 20));
    finishBody();
    await new Promise((resolve) => setTimeout(resolve, 10));
    finishRelease();

    await expect(raced).rejects.toThrow('the scenario did not finish within 5ms');
  });

  it('rejects on the deadline even when the release fails', async () => {
    const expiry = withDeadline(new Promise(() => {}), 5, 'the scenario', () =>
      Promise.reject(new Error('the mount would not release'))
    );
    await expect(expiry).rejects.toThrow('the scenario did not finish within 5ms');
  });
});
