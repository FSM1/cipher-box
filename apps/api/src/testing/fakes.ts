import { ConfigService } from '@nestjs/config';
import { Clock } from '../common/clock';
import { Entropy } from '../common/entropy';

export class FakeClock extends Clock {
  private current: Date;

  constructor(start = new Date('2026-01-01T00:00:00Z')) {
    super();
    this.current = start;
  }

  now(): Date {
    return new Date(this.current);
  }

  advanceMs(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
}

/** Deterministic, collision-free byte source: a big-endian counter. */
export class FakeEntropy extends Entropy {
  private counter = 0;

  randomBytes(length: number): Buffer {
    const buffer = Buffer.alloc(length);
    this.counter += 1;
    buffer.writeUInt32BE(this.counter, length - 4);
    return buffer;
  }
}

/** Mutable ConfigService stand-in backed by a plain object. */
export function fakeConfig(values: Record<string, string | undefined>): {
  service: ConfigService;
  values: Record<string, string | undefined>;
} {
  const service = {
    get: (key: string) => values[key],
  } as unknown as ConfigService;
  return { service, values };
}
