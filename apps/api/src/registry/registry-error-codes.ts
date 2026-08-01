/**
 * The registry's batch routes answer 400 for a refusal the caller can never
 * retry past — an over-cap batch, an over-cap `contentCids`, a malformed entry.
 * The body carries a stable `code` so a client classifies on it instead of
 * parsing `message`, and so a 400 from anything that is NOT this gate (a proxy,
 * a body-size cap) stays unattributable (#920, mirroring the 413 codes #842).
 */
export const REGISTRY_BATCH_REFUSED = 'REGISTRY_BATCH_REFUSED';

/**
 * The 400 body the register/retire pipes emit. Nest stops synthesizing
 * `statusCode`/`error` as soon as an exception is given an object, so the full
 * envelope is built here once rather than re-typed at each throw site.
 */
export function batchRefusedBody(message: unknown) {
  return { statusCode: 400, message, error: 'Bad Request', code: REGISTRY_BATCH_REFUSED };
}
