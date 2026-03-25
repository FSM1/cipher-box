const PERF_ENABLED =
  typeof performance !== 'undefined' &&
  typeof performance.mark === 'function' &&
  ((typeof globalThis !== 'undefined' && (globalThis as any).__CIPHERBOX_PERF__) ||
    (typeof process !== 'undefined' &&
      typeof process.env?.NODE_ENV === 'string' &&
      process.env.NODE_ENV !== 'production'));

let perfCounter = 0;

export function markStart(operation: string): string {
  if (!PERF_ENABLED) return '';
  const id = ++perfCounter;
  const markName = `cipherbox:${operation}:${id}:start`;
  performance.mark(markName);
  return markName;
}

export function markEnd(operation: string, startMark: string): PerformanceMeasure | null {
  if (!PERF_ENABLED || !startMark) return null;
  const id = startMark.match(/:(\d+):start$/)?.[1] ?? '0';
  const endMark = `cipherbox:${operation}:${id}:end`;
  performance.mark(endMark);
  const measureName = `cipherbox:${operation}`;
  const measure = performance.measure(measureName, startMark, endMark);
  performance.clearMarks(startMark);
  performance.clearMarks(endMark);
  performance.clearMeasures(measureName);
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
