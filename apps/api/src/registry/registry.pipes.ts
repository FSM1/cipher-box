import { BadRequestException, ParseArrayPipe, PipeTransform } from '@nestjs/common';
import { ValidationError } from 'class-validator';
import { MAX_BATCH, REGISTER_ARRAY_OPTIONS, RETIRE_ARRAY_OPTIONS } from './dto/registry.dto';
import { batchRefusedBody } from './registry-error-codes';

/** The constraint strings alone: a validation error also carries the rejected
 * entry, and echoing a caller's whole batch back into an error body puts its
 * names and CIDs everywhere the response is logged. */
function constraintMessages(errors: ValidationError[]): string[] {
  return errors.flatMap((error) => [
    ...Object.values(error.constraints ?? {}),
    ...constraintMessages(error.children ?? []),
  ]);
}

/** `ParseArrayPipe` hands its `exceptionFactory` already-flattened strings; the
 * size and length guards hand a single string. */
function messagesOf(error: unknown): string[] {
  if (!Array.isArray(error)) return [String(error)];
  return error.every((item) => item instanceof ValidationError)
    ? constraintMessages(error)
    : error.map(String);
}

/** Every batch-gate refusal answers the one documented body (see its home). */
const refuse = (error: unknown) => new BadRequestException(batchRefusedBody(messagesOf(error)));

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

/**
 * Cap the retire batch on its TOTAL target count: an entry carries a target
 * list, so the entry count alone bounds nothing.
 */
class TargetCountPipe implements PipeTransform {
  constructor(private readonly max: number) {}

  transform(value: unknown): unknown {
    if (!Array.isArray(value)) {
      return value;
    }
    let total = 0;
    for (const entry of value) {
      const targets = (entry as { targets?: unknown })?.targets;
      total += Array.isArray(targets) ? targets.length : 0;
      if (total > this.max) {
        throw refuse(`Batch exceeds ${this.max} targets`);
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

/** Size guards first, then the retire DTO validation. */
export const retireBodyPipes = [
  new BatchSizePipe(MAX_BATCH, 'entries'),
  new TargetCountPipe(MAX_BATCH),
  new ParseArrayPipe({ ...RETIRE_ARRAY_OPTIONS, exceptionFactory: refuse }),
];
