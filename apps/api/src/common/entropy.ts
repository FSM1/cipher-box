import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

/**
 * Injectable entropy source. Nonces, refresh tokens, and family ids draw
 * from here so tests can seed them deterministically.
 */
@Injectable()
export abstract class Entropy {
  abstract randomBytes(length: number): Buffer;

  /** RFC 4122 v4 UUID formatted from 16 random bytes. */
  randomUuid(): string {
    const bytes = this.randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
}

@Injectable()
export class SystemEntropy extends Entropy {
  randomBytes(length: number): Buffer {
    return randomBytes(length);
  }
}
