import { BadRequestException, ParseArrayPipe, PipeTransform } from '@nestjs/common';
import {
  MAX_BATCH,
  REGISTER_ARRAY_OPTIONS,
  RETIRE_ARRAY_OPTIONS,
  RETIRE_TARGET_MAX_LENGTH,
} from './dto/registry.dto';
import { batchRefusedBody } from './registry-error-codes';

/** Every batch-gate refusal carries the same stable `code` (see its home). */
const refuse = (message: unknown) => new BadRequestException(batchRefusedBody(message));

/** Reject an oversize batch up front, before per-item validation runs. */
class BatchSizePipe implements PipeTransform {
  constructor(
    private readonly max: number,
    private readonly noun: string
  ) {}

  transform(value: unknown): unknown {
    if (Array.isArray(value) && value.length > this.max) {
      throw refuse(`Batch exceeds ${this.max} ${this.noun}`);
    }
    return value;
  }
}

/** Cap each retire target's length; ParseArrayPipe never reaches items. */
class TargetLengthPipe implements PipeTransform {
  constructor(private readonly max: number) {}

  transform(value: string[]): string[] {
    for (const target of value) {
      if (target.length > this.max) {
        throw refuse(`target exceeds ${this.max} characters`);
      }
    }
    return value;
  }
}

/** Size guard first, then the register DTO validation. */
export const registerBodyPipes = [
  new BatchSizePipe(MAX_BATCH, 'entries'),
  new ParseArrayPipe({ ...REGISTER_ARRAY_OPTIONS, exceptionFactory: refuse }),
];

/** Size guard first, then array parse, then the per-target length cap. */
export const retireBodyPipes = [
  new BatchSizePipe(MAX_BATCH, 'targets'),
  new ParseArrayPipe({ ...RETIRE_ARRAY_OPTIONS, exceptionFactory: refuse }),
  new TargetLengthPipe(RETIRE_TARGET_MAX_LENGTH),
];
