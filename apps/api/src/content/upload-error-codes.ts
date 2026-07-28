/**
 * `POST /content/upload` answers 413 for two unrelated causes, so the body
 * carries a stable `code` a client classifies on instead of parsing `message`
 * (#842): the transport cap is permanent for the request, the quota gate clears
 * once the account frees space.
 */
export const UPLOAD_TOO_LARGE = 'UPLOAD_TOO_LARGE';
export const QUOTA_EXCEEDED = 'QUOTA_EXCEEDED';

export type UploadTooLargeCode = typeof UPLOAD_TOO_LARGE | typeof QUOTA_EXCEEDED;

/**
 * The 413 body both producers emit. Nest stops synthesizing `statusCode`/
 * `error` as soon as an exception is given an object, so the full envelope is
 * built here once rather than re-typed at each throw site.
 */
export function uploadTooLargeBody(code: UploadTooLargeCode, message: string) {
  return { statusCode: 413, message, error: 'Payload Too Large', code };
}
