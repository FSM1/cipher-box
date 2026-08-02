/** Renders an unknown throw as the one line a wire message or log carries. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
