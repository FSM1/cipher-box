import { ApiProperty } from '@nestjs/swagger';

/**
 * The registry's batch routes answer 400 for a refusal the caller can never
 * retry past. Clients classify on this stable `code`, so a 400 from anything
 * that is NOT this gate stays unattributable (blueprint/api.md).
 */
export const REGISTRY_BATCH_REFUSED = 'REGISTRY_BATCH_REFUSED';

/** The documented 400 body; `batchRefusedBody` returns exactly this shape. */
export class BatchRefusedDto {
  @ApiProperty({ example: 400 })
  statusCode!: number;

  @ApiProperty({
    type: [String],
    description: 'Constraint strings only — never the rejected entry',
  })
  message!: string[];

  @ApiProperty({ example: 'Bad Request' })
  error!: string;

  @ApiProperty({ enum: [REGISTRY_BATCH_REFUSED] })
  code!: string;
}

/** Nest stops synthesizing `statusCode`/`error` once an exception carries an
 * object, so the whole envelope is built here rather than at each throw site. */
export function batchRefusedBody(message: string[]): BatchRefusedDto {
  return { statusCode: 400, message, error: 'Bad Request', code: REGISTRY_BATCH_REFUSED };
}
