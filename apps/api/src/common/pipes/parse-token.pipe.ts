import { PipeTransform, Injectable, BadRequestException } from '@nestjs/common';

/**
 * Validates that a path parameter looks like a base64url token.
 * Tokens are generated via randomBytes(16).toString('base64url') = 22 chars.
 * Accepts 16-44 chars of [A-Za-z0-9_-] to allow reasonable variation.
 *
 * Rejects obviously malformed tokens without hitting the database.
 */
@Injectable()
export class ParseTokenPipe implements PipeTransform<string, string> {
  private static readonly TOKEN_REGEX = /^[A-Za-z0-9_-]{16,44}$/;

  transform(value: string): string {
    if (!ParseTokenPipe.TOKEN_REGEX.test(value)) {
      throw new BadRequestException('Invalid token format');
    }
    return value;
  }
}
