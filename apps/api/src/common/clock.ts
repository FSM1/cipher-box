import { Injectable } from '@nestjs/common';

/**
 * Injectable time source. Services never call `Date.now()` directly —
 * determinism is injected (AGENTS.md, code generation rule 4), so tests
 * drive expiry and rotation timelines with a fake clock.
 */
@Injectable()
export abstract class Clock {
  abstract now(): Date;
}

@Injectable()
export class SystemClock extends Clock {
  now(): Date {
    return new Date();
  }
}
