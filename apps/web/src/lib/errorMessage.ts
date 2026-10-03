/** Renders an unknown throw as the one line the UI shows for it. */
export function errorMessage(failure: unknown): string {
  if (failure instanceof Error) return failure.message;
  if (isRefusedRequest(failure)) {
    return `the request to ${hostOf(failure.url)} failed with status ${failure.status}`;
  }
  return String(failure);
}

// The Web3Auth HTTP helpers throw the raw `Response` of a refused request. Its
// body and query can carry a token, so only the host and the status are read.
// A shape check, because a library bundle can hold its own `Response` class.
function isRefusedRequest(failure: unknown): failure is { status: number; url: string } {
  if (typeof failure !== 'object' || failure === null) return false;
  const { status, url } = failure as { status?: unknown; url?: unknown };
  return typeof status === 'number' && typeof url === 'string';
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'an unknown host';
  }
}
