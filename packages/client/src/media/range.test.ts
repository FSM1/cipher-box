import { describe, expect, it } from 'vitest';

import { resolveMediaRequest, type MediaHead, type MediaWindow } from './range.js';

const SIZE = 4096;
const MIME = 'video/mp4';

/** The first integer past `Number.MAX_SAFE_INTEGER`. */
const UNSAFE = '9007199254740992';

const headerMap = (head: MediaHead): Map<string, string> => new Map(head.headers);

const windowOf = (head: MediaHead): MediaWindow => {
  if (head.status === 416) throw new Error('a 416 head carries no window');
  return head.window;
};

const contentTypeFor = (mimeType: string): string | undefined =>
  headerMap(resolveMediaRequest(null, SIZE, { mimeType })).get('content-type');

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
    const head = resolveMediaRequest('bytes=0-99', SIZE, { mimeType: 'text/html' });
    expect(head.status).toBe(206);
    expect(headerMap(head).get('content-type')).toBe('application/octet-stream');
  });
});

describe('resolveMediaRequest hardening headers', () => {
  const cases: Array<[string, MediaHead]> = [
    ['200', resolveMediaRequest(null, SIZE, { mimeType: MIME })],
    ['206', resolveMediaRequest('bytes=0-99', SIZE, { mimeType: MIME })],
    ['416', resolveMediaRequest(`bytes=${SIZE}-`, SIZE, { mimeType: MIME })],
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

describe('resolveMediaRequest 206 windows', () => {
  const cases: Array<{ spec: string; offset: number; length: number }> = [
    { spec: 'bytes=0-99', offset: 0, length: 100 },
    { spec: 'bytes=4095-4095', offset: 4095, length: 1 },
    { spec: 'bytes=4000-', offset: 4000, length: 96 },
    // A last past EOF clamps to the last byte rather than over-reading.
    { spec: 'bytes=4000-999999', offset: 4000, length: 96 },
    { spec: 'bytes=-100', offset: 3996, length: 100 },
    { spec: 'bytes=-1', offset: 4095, length: 1 },
    // A suffix longer than the file is the whole file, not a 416.
    { spec: 'bytes=-99999', offset: 0, length: SIZE },
    { spec: 'BYTES=0-99', offset: 0, length: 100 },
    { spec: '  bytes= 1000-1999 ', offset: 1000, length: 1000 },
  ];

  for (const { spec, offset, length } of cases) {
    it(`serves '${spec}' as ${length} bytes from ${offset}`, () => {
      const head = resolveMediaRequest(spec, SIZE, { mimeType: MIME });

      expect(head.status).toBe(206);
      expect(windowOf(head)).toEqual({ offset, length });
      const headers = headerMap(head);
      expect(headers.get('content-range')).toBe(`bytes ${offset}-${offset + length - 1}/${SIZE}`);
      expect(headers.get('content-length')).toBe(String(length));
    });
  }
});

describe('resolveMediaRequest whole-file fall-through', () => {
  const cases: Array<[string, string | null]> = [
    ['an absent Range header', null],
    ['a blank Range header', '   '],
    ['a multi-range set', 'bytes=0-99,200-299'],
    ['a non-bytes unit', 'items=0-99'],
    ['a malformed spec', 'bytes=abc'],
    ['an empty spec', 'bytes='],
    ['a bare dash', 'bytes=-'],
  ];

  for (const [name, spec] of cases) {
    it(`answers ${name} with the whole file`, () => {
      const head = resolveMediaRequest(spec, SIZE, { mimeType: MIME });

      expect(head.status).toBe(200);
      expect(windowOf(head)).toEqual({ offset: 0, length: SIZE });
      const headers = headerMap(head);
      expect(headers.get('content-length')).toBe(String(SIZE));
      expect(headers.has('content-range')).toBe(false);
    });
  }

  it('answers an empty file with an empty window', () => {
    const head = resolveMediaRequest(null, 0, { mimeType: MIME });

    expect(head.status).toBe(200);
    expect(windowOf(head)).toEqual({ offset: 0, length: 0 });
  });
});

describe('resolveMediaRequest 416', () => {
  const cases: Array<[string, string, number]> = [
    ['an offset at EOF', `bytes=${SIZE}-`, SIZE],
    ['an inverted interval', 'bytes=100-50', SIZE],
    ['a zero-length suffix', 'bytes=-0', SIZE],
    ['any suffix of an empty file', 'bytes=-10', 0],
    ['an interval on an empty file', 'bytes=0-9', 0],
    ['an offset past MAX_SAFE_INTEGER', `bytes=${UNSAFE}-`, SIZE],
    ['a last past MAX_SAFE_INTEGER', `bytes=0-${UNSAFE}`, SIZE],
    ['a suffix past MAX_SAFE_INTEGER', `bytes=-${UNSAFE}`, SIZE],
  ];

  for (const [name, spec, size] of cases) {
    it(`rejects ${name} with no window`, () => {
      const head = resolveMediaRequest(spec, size, { mimeType: MIME });

      expect(head.status).toBe(416);
      // A rejected range must read no plaintext at all.
      expect('window' in head).toBe(false);
      const headers = headerMap(head);
      expect(headers.get('content-range')).toBe(`bytes */${size}`);
      expect(headers.has('content-length')).toBe(false);
    });
  }
});

describe('resolveMediaRequest content-disposition', () => {
  const dispositionFor = (downloadName: string, spec: string | null = null): string | undefined =>
    headerMap(resolveMediaRequest(spec, SIZE, { mimeType: MIME, downloadName })).get(
      'content-disposition'
    );

  it('renders rather than saves when no name is given', () => {
    expect(
      headerMap(resolveMediaRequest(null, SIZE, { mimeType: MIME })).has('content-disposition')
    ).toBe(false);
  });

  it('saves under the name it is given, whole file or range', () => {
    expect(dispositionFor('notes.md')).toBe("attachment; filename*=UTF-8''notes.md");
    expect(dispositionFor('notes.md', 'bytes=0-99')).toBe("attachment; filename*=UTF-8''notes.md");
  });

  it('percent-encodes anything that could forge a header or a second parameter', () => {
    // A quote, a semicolon and a newline are what a name would need to break
    // out of this header; a space and a comma are simply not `attr-char`.
    expect(dispositionFor('a"b;c\r\nd e,f')).toBe(
      "attachment; filename*=UTF-8''a%22b%3Bc%0D%0Ad%20e%2Cf"
    );
  });

  it('encodes a non-ASCII name as UTF-8 bytes', () => {
    expect(dispositionFor('naïve — ☃.txt')).toBe(
      "attachment; filename*=UTF-8''na%C3%AFve%20%E2%80%94%20%E2%98%83.txt"
    );
  });

  it('still saves when a name encodes to nothing', () => {
    expect(dispositionFor('')).toBe('attachment');
  });
});
