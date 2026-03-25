const PERF_ENABLED =
  typeof performance !== 'undefined' &&
  typeof performance.mark === 'function' &&
  ((typeof globalThis !== 'undefined' && (globalThis as any).__CIPHERBOX_PERF__) ||
    (typeof process !== 'undefined' && process.env.NODE_ENV !== 'production'));

export function markStart(operation: string): string {
  if (!PERF_ENABLED) return '';
  const markName = `cipherbox:${operation}:start`;
  performance.mark(markName);
  return markName;
}

export function markEnd(operation: string, startMark: string): PerformanceMeasure | null {
  if (!PERF_ENABLED || !startMark) return null;
  const endMark = `cipherbox:${operation}:end`;
  performance.mark(endMark);
  const measure = performance.measure(`cipherbox:${operation}`, startMark, endMark);
  performance.clearMarks(startMark);
  performance.clearMarks(endMark);
  return measure;
}

export async function withPerf<T>(operation: string, fn: () => Promise<T>): Promise<T> {
  const start = markStart(operation);
  try {
    return await fn();
  } finally {
    markEnd(operation, start);
  }
}
