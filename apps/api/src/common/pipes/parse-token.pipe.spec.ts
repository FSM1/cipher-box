import { BadRequestException } from '@nestjs/common';
import { ParseTokenPipe } from './parse-token.pipe';

describe('ParseTokenPipe', () => {
  let pipe: ParseTokenPipe;

  beforeEach(() => {
    pipe = new ParseTokenPipe();
  });

  describe('valid tokens', () => {
    it('should accept a standard 22-char base64url token', () => {
      // randomBytes(16).toString('base64url') = 22 chars
      const token = 'abcdefghijklmnopqrstuv';
      expect(pipe.transform(token)).toBe(token);
    });

    it('should accept tokens with base64url special chars (_-)', () => {
      const token = 'abc_def-ghijklmnopqrst';
      expect(pipe.transform(token)).toBe(token);
    });

    it('should accept minimum length (16 chars)', () => {
      const token = 'a'.repeat(16);
      expect(pipe.transform(token)).toBe(token);
    });

    it('should accept maximum length (44 chars)', () => {
      const token = 'a'.repeat(44);
      expect(pipe.transform(token)).toBe(token);
    });

    it('should accept tokens with digits', () => {
      const token = '0123456789abcdef0123';
      expect(pipe.transform(token)).toBe(token);
    });
  });

  describe('invalid tokens', () => {
    it('should reject empty string', () => {
      expect(() => pipe.transform('')).toThrow(BadRequestException);
    });

    it('should reject too-short tokens (< 16 chars)', () => {
      expect(() => pipe.transform('abc')).toThrow(BadRequestException);
    });

    it('should reject too-long tokens (> 44 chars)', () => {
      expect(() => pipe.transform('a'.repeat(45))).toThrow(BadRequestException);
    });

    it('should reject tokens with spaces', () => {
      expect(() => pipe.transform('abc def ghi jkl mnop')).toThrow(BadRequestException);
    });

    it('should reject tokens with special characters', () => {
      expect(() => pipe.transform('abc!@#$%^&*()_=+;:,')).toThrow(BadRequestException);
    });

    it('should reject tokens with slashes', () => {
      expect(() => pipe.transform('abc/def/ghi/jkl/mnop')).toThrow(BadRequestException);
    });

    it('should reject tokens with plus (base64 but not base64url)', () => {
      expect(() => pipe.transform('abc+def+ghi+jkl+mnop')).toThrow(BadRequestException);
    });

    it('should reject tokens with equals (padding)', () => {
      expect(() => pipe.transform('abcdefghijklmnop====')).toThrow(BadRequestException);
    });

    it('should reject SQL injection attempt', () => {
      expect(() => pipe.transform("'; DROP TABLE--")).toThrow(BadRequestException);
    });

    it('should reject path traversal attempt', () => {
      expect(() => pipe.transform('../../../etc/passwd')).toThrow(BadRequestException);
    });
  });
});
