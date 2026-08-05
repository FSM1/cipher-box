/** Renders an unknown throw as the one line a wire message or log carries. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Renders an unknown throw as an `Error`, so a rejection carries a stack. */
export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
