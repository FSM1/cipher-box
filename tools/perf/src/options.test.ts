import { describe, expect, it } from 'vitest';
import { command, parseOptions } from './options';
import { BASELINE_SCENARIOS } from './report';

describe('parseOptions', () => {
  it('covers every baseline scenario when none is named', () => {
    expect(parseOptions(['--target', 'local']).scenarios).toEqual([...BASELINE_SCENARIOS]);
  });

  it('keeps the named scenarios in the order they were given', () => {
    const options = parseOptions([
      '--target',
      'staging',
      '--scenario',
      'mixed',
      '--scenario',
      'name-wave',
    ]);
    expect(options.scenarios).toEqual(['mixed', 'name-wave']);
    expect(options.target).toBe('staging');
  });

  it('refuses a target that is neither local nor staging', () => {
    expect(() => parseOptions(['--target', 'production'])).toThrow(/local or staging/);
  });

  it('refuses a scenario the harness does not have', () => {
    expect(() => parseOptions(['--target', 'local', '--scenario', 'spike-test'])).toThrow(
      /unknown scenario/
    );
  });

  it('refuses a flag that was given no value', () => {
    expect(() => parseOptions(['--target', 'local', '--clients'])).toThrow(/expects a value/);
    expect(() => parseOptions(['--target', 'local', '--clients', '--ops-per-client'])).toThrow(
      /expects a value/
    );
  });

  it('refuses a flag it does not know', () => {
    expect(() => parseOptions(['--target', 'local', '--threads', '4'])).toThrow(/unknown flag/);
  });
});

describe('command', () => {
  const options = parseOptions(['--target', 'local', '--clients', '7', '--ops-per-client', '9']);

  it('passes every dimension to the harness as separate arguments', () => {
    const { file, args } = command(options, 'mixed', '/somewhere/cipherbox-load');
    expect(file).toBe('/somewhere/cipherbox-load');
    expect(args).toEqual([
      '--scenario',
      'mixed',
      '--target',
      'local',
      '--clients',
      '7',
      '--ops-per-client',
      '9',
      '--report-dir',
      'load-reports',
    ]);
  });

  it('builds the harness through cargo when no binary is named', () => {
    const { file, args } = command(options, 'mixed', undefined);
    expect(file).toBe('cargo');
    expect(args.slice(0, 5)).toEqual(['run', '--release', '-p', 'cipherbox-load', '--']);
  });

  it('never places a credential on the command line', () => {
    const { args } = command(options, 'mixed', undefined);
    expect(args).not.toContain('--secret');
    expect(args.join(' ')).not.toMatch(/secret|token/i);
  });
});
