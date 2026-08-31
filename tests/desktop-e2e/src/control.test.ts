import { describe, expect, it } from 'vitest';
import { formatRequest, parseControlFile, parseResponse, type VaultStatus } from './control';

const TOKEN = 'a'.repeat(64);

const MOUNTED: VaultStatus = {
  items: 2,
  staleness: 'fresh',
  deadLetters: 0,
  provisioned: true,
  warnings: [],
  mount: { state: 'mounted', path: '/tmp/home/CipherBox' },
};

describe('parseControlFile', () => {
  it('reads the port and the token off a well-formed line', () => {
    expect(parseControlFile(`51234 ${TOKEN}\n`)).toEqual({ port: 51234, token: TOKEN });
  });

  it('refuses an empty file', () => {
    expect(() => parseControlFile('')).toThrow(/empty/);
    expect(() => parseControlFile('\n')).toThrow(/empty/);
  });

  it('refuses a second line', () => {
    expect(() => parseControlFile(`51234 ${TOKEN}\n51235 ${TOKEN}\n`)).toThrow(/2 lines/);
  });

  it('refuses an extra field', () => {
    expect(() => parseControlFile(`51234 ${TOKEN} extra\n`)).toThrow(/3 fields/);
  });

  it('refuses an absent field', () => {
    expect(() => parseControlFile('51234\n')).toThrow(/1 fields/);
  });

  it('refuses a port that is not a number', () => {
    expect(() => parseControlFile(`port ${TOKEN}\n`)).toThrow(/not a number/);
  });

  it('refuses a port outside the range a listener can bind', () => {
    expect(() => parseControlFile(`0 ${TOKEN}\n`)).toThrow(/outside/);
    expect(() => parseControlFile(`65536 ${TOKEN}\n`)).toThrow(/outside/);
  });

  it('refuses a token that is not 64 lowercase hex characters', () => {
    expect(() => parseControlFile('51234 short\n')).toThrow(/64 lowercase hex/);
    expect(() => parseControlFile(`51234 ${'A'.repeat(64)}\n`)).toThrow(/64 lowercase hex/);
    expect(() => parseControlFile(`51234 ${'a'.repeat(65)}\n`)).toThrow(/64 lowercase hex/);
  });

  it('keeps the token out of the message it raises', () => {
    const badToken = 'f'.repeat(63);
    let message = '';
    try {
      parseControlFile(`51234 ${badToken}\n`);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toContain(badToken);
  });
});

describe('formatRequest', () => {
  it('sends the token and the verb on one terminated line', () => {
    expect(formatRequest({ port: 1, token: TOKEN }, 'status')).toBe(`${TOKEN} status\n`);
  });
});

describe('parseResponse', () => {
  it('reads a status answer', () => {
    const answer = parseResponse(JSON.stringify({ ok: true, status: MOUNTED }));
    expect(answer.ok).toBe(true);
    expect(answer.ok && answer.status).toEqual(MOUNTED);
  });

  it('reads a bare acknowledgement', () => {
    const answer = parseResponse('{"ok":true}');
    expect(answer.ok).toBe(true);
    expect(answer.ok && answer.status).toBeUndefined();
  });

  it('reads a refusal and keeps its reason', () => {
    const answer = parseResponse('{"ok":false,"error":"unknown verb"}');
    expect(answer.ok).toBe(false);
    expect(!answer.ok && answer.error).toBe('unknown verb');
  });

  it('names a refusal that carried no reason', () => {
    const answer = parseResponse('{"ok":false}');
    expect(!answer.ok && answer.error).toBe('no reason given');
  });

  it('refuses a non-JSON answer', () => {
    expect(() => parseResponse('not json at all')).toThrow(/non-JSON/);
  });

  it('refuses a truncated answer', () => {
    expect(() => parseResponse('{"ok":true,"status":{')).toThrow(/non-JSON/);
  });

  it('refuses an answer that is not an object', () => {
    expect(() => parseResponse('[1,2,3]')).toThrow(/not an object/);
    expect(() => parseResponse('null')).toThrow(/not an object/);
    expect(() => parseResponse('"ok"')).toThrow(/not an object/);
  });

  it('refuses an answer with no ok field', () => {
    expect(() => parseResponse('{"status":{}}')).toThrow(/no ok field/);
  });

  it('refuses an ok field that is not a boolean', () => {
    expect(() => parseResponse('{"ok":"true"}')).toThrow(/no ok field/);
  });

  it('shortens a long unparseable answer rather than a repeat of all of it', () => {
    let message = '';
    try {
      parseResponse('x'.repeat(500));
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message.length).toBeLessThan(300);
  });
});
