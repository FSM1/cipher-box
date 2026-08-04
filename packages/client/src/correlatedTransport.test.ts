import { describe, expect, it } from 'vitest';

import {
  EngineRequestError,
  engineErrorCode,
  isRecoverableEngineError,
} from './correlatedTransport.js';

describe('engineErrorCode', () => {
  it('reads the code off an engine failure and nothing else', () => {
    expect(engineErrorCode(new EngineRequestError('nope', 'unknownNode'))).toBe('unknownNode');
    expect(engineErrorCode(new EngineRequestError('nope'))).toBeUndefined();
    expect(engineErrorCode(new Error('transport died'))).toBeUndefined();
    expect(engineErrorCode({ code: 'trustViolation' })).toBeUndefined();
  });
});

describe('isRecoverableEngineError', () => {
  it('recognises the open-stream ceiling', () => {
    expect(isRecoverableEngineError('tooManyStreams')).toBe(true);
  });

  // This predicate gates the media broker's reclaim-and-retry, so a fail-closed
  // verdict widening into it would turn a trust refusal into a retry loop.
  it.each([
    'trustViolation',
    'coldStart',
    'contentUnavailable',
    'contentKeySealFailed',
    'unsupportedContentFormat',
    'unknownStreamHandle',
    'auth',
    'invalidSecret',
    'seam',
    undefined,
  ])('never treats %s as recoverable', (code) => {
    expect(isRecoverableEngineError(code)).toBe(false);
  });
});
