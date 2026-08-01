/** Renders an unknown throw as the one line the UI shows for it. */
export function errorMessage(failure: unknown): string {
  return failure instanceof Error ? failure.message : String(failure);
}
