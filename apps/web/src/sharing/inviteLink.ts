/** The claim route, so the mint and the router name one destination. */
export const INVITE_ROUTE = '/invite';

/**
 * The link an owner hands out. The engine's fragment is the whole capability and
 * rides the URL fragment, which no browser sends to a server; it is base64url,
 * so it needs no escaping and reaches the claim verbatim.
 */
export function inviteUrl(origin: string, fragment: string): string {
  return `${origin}${INVITE_ROUTE}#${fragment}`;
}
