import { describe, it, expect } from 'vitest';
import { selectEncryptionMode, normalizeEncryptionMode } from '../encryption-mode';

describe('selectEncryptionMode', () => {
  const LARGE = 512 * 1024; // 512KB — above 256KB threshold
  const SMALL = 100 * 1024; // 100KB — below threshold

  it('returns CTR for large video/mp4', () => {
    expect(selectEncryptionMode('video/mp4', LARGE)).toBe('CTR');
  });

  it('returns CTR for large video/webm', () => {
    expect(selectEncryptionMode('video/webm', LARGE)).toBe('CTR');
  });

  it('returns CTR for large audio/mpeg', () => {
    expect(selectEncryptionMode('audio/mpeg', LARGE)).toBe('CTR');
  });

  it('returns CTR for large audio/flac', () => {
    expect(selectEncryptionMode('audio/flac', LARGE)).toBe('CTR');
  });

  it('returns GCM for small video (below threshold)', () => {
    expect(selectEncryptionMode('video/mp4', SMALL)).toBe('GCM');
  });

  it('returns GCM for exactly 256KB (not above threshold)', () => {
    expect(selectEncryptionMode('video/mp4', 256 * 1024)).toBe('GCM');
  });

  it('returns CTR for 256KB + 1 byte', () => {
    expect(selectEncryptionMode('video/mp4', 256 * 1024 + 1)).toBe('CTR');
  });

  it('returns GCM for non-media MIME type regardless of size', () => {
    expect(selectEncryptionMode('application/pdf', LARGE)).toBe('GCM');
    expect(selectEncryptionMode('text/plain', LARGE)).toBe('GCM');
    expect(selectEncryptionMode('image/png', LARGE)).toBe('GCM');
  });

  it('returns GCM for unsupported audio MIME type', () => {
    expect(selectEncryptionMode('audio/wav', LARGE)).toBe('GCM');
  });
});

describe('normalizeEncryptionMode', () => {
  it('returns CTR for "CTR"', () => {
    expect(normalizeEncryptionMode('CTR')).toBe('CTR');
  });

  it('returns GCM for "GCM"', () => {
    expect(normalizeEncryptionMode('GCM')).toBe('GCM');
  });

  it('returns GCM for undefined', () => {
    expect(normalizeEncryptionMode(undefined)).toBe('GCM');
  });

  it('returns GCM for invalid string', () => {
    expect(normalizeEncryptionMode('INVALID')).toBe('GCM');
    expect(normalizeEncryptionMode('ctr')).toBe('GCM');
    expect(normalizeEncryptionMode('')).toBe('GCM');
  });
});
