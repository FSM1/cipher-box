import { describe, expect, it } from 'vitest';

import { resolveMediaRequest, type MediaHead } from './range.js';

const SIZE = 4096;

const headerMap = (head: MediaHead): Map<string, string> => new Map(head.headers);

const contentTypeFor = (mimeType: string): string | undefined =>
  headerMap(resolveMediaRequest(null, SIZE, mimeType)).get('content-type');

describe('resolveMediaRequest content-type', () => {
  it('downgrades a type that would execute on the app origin', () => {
    expect(contentTypeFor('text/html')).toBe('application/octet-stream');
    expect(contentTypeFor('image/svg+xml')).toBe('application/octet-stream');
    expect(contentTypeFor('application/javascript')).toBe('application/octet-stream');
  });

  it('passes a playable media type through', () => {
    expect(contentTypeFor('video/mp4')).toBe('video/mp4');
    expect(contentTypeFor('audio/mpeg')).toBe('audio/mpeg');
    expect(contentTypeFor('image/png')).toBe('image/png');
  });

  it('downgrades on the 206 head too', () => {
    const head = resolveMediaRequest('bytes=0-99', SIZE, 'text/html');
    expect(head.status).toBe(206);
    expect(headerMap(head).get('content-type')).toBe('application/octet-stream');
  });
});

describe('resolveMediaRequest hardening headers', () => {
  const cases: Array<[string, MediaHead]> = [
    ['200', resolveMediaRequest(null, SIZE, 'video/mp4')],
    ['206', resolveMediaRequest('bytes=0-99', SIZE, 'video/mp4')],
    ['416', resolveMediaRequest(`bytes=${SIZE}-`, SIZE, 'video/mp4')],
  ];

  for (const [status, head] of cases) {
    it(`sets nosniff and a no-source content-security-policy on the ${status} head`, () => {
      expect(String(head.status)).toBe(status);
      const headers = headerMap(head);
      expect(headers.get('x-content-type-options')).toBe('nosniff');
      expect(headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
    });
  }
});
