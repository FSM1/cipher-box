import { ExecutionContext } from '@nestjs/common';

/**
 * The `route` metric label. The matched route template, never the raw URL:
 * a label's cardinality is the route table's, and a raw path would carry
 * account-identifying segments into an unauthenticated `/metrics` read.
 */
export function routeLabel(request: { route?: { path?: string } }): string {
  return request.route?.path ?? 'unmatched';
}

/** {@link routeLabel} for a caller that holds the context rather than the request. */
export function routeLabelFor(context: ExecutionContext): string {
  return routeLabel(context.switchToHttp().getRequest<{ route?: { path?: string } }>());
}
