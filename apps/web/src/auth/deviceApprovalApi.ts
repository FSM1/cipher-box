/**
 * The rendezvous a requesting device speaks (FSM1/cipher-box-next ADR 0009 D1).
 *
 * Spoken over plain HTTP for the same reason `@cipherbox/login`'s identity
 * exchange is: this device has no vault key yet, so the engine has no session to
 * speak through. The approver's half of the exchange needs a full account
 * session and therefore runs through the engine instead.
 *
 * Every value here is opaque hex, base64 or an id. Nothing is derived and
 * nothing is verified in this file — the engine owns both.
 */

/** The scoped pre-reconstruction token, held in memory for one rendezvous only. */
export interface ApprovalSession {
  /** Open a rendezvous, signed over the key it offers. */
  open(
    devicePublicKey: string,
    ephemeralPublicKey: string,
    signature: string
  ): Promise<OpenedRendezvous>;
  /** Poll it. A settled rendezvous is served once and its row is then gone. */
  poll(requestId: string): Promise<RendezvousState>;
  /** Abandon it. Best effort: a rendezvous also expires on its own. */
  abandon(requestId: string): Promise<void>;
}

export interface OpenedRendezvous {
  requestId: string;
  /** ISO 8601; the row is gone at this instant. */
  expiresAt: string;
}

/** Where a rendezvous stands. `gone` covers expiry and an answer already read. */
export type RendezvousState =
  | { status: 'pending'; expiresAt: string }
  | { status: 'approved'; sealedFactor: string }
  | { status: 'denied' }
  | { status: 'gone' };

interface StatusBody {
  status: string;
  expiresAt: string;
  sealedFactor?: string;
}

/**
 * Exchange a CipherBox identity token for the scoped token the rendezvous
 * routes take. The token stays in this closure: it reaches no storage, and it
 * dies with the tab.
 */
export async function openApprovalSession(
  apiBaseUrl: string,
  identityToken: string
): Promise<ApprovalSession> {
  const base = apiBaseUrl.replace(/\/+$/, '');
  const minted = await request(base, 'POST', '/device-approval/session', null, {
    body: { identityToken },
  });
  const accessToken = readAccessToken(minted);

  return {
    async open(devicePublicKey, ephemeralPublicKey, signature) {
      const body = await request(base, 'POST', '/device-approval/requests', accessToken, {
        body: { devicePublicKey, ephemeralPublicKey, signature },
      });
      const opened = body as Partial<OpenedRendezvous>;
      if (typeof opened.requestId !== 'string' || typeof opened.expiresAt !== 'string') {
        throw new Error('the rendezvous did not open');
      }
      return { requestId: opened.requestId, expiresAt: opened.expiresAt };
    },

    async poll(requestId) {
      let body: unknown;
      try {
        body = await request(
          base,
          'GET',
          `/device-approval/requests/${pathId(requestId)}`,
          accessToken,
          {
            goneOn404: true,
          }
        );
      } catch (refusal) {
        // A collected or expired row is a 404 by design, and it is the ordinary
        // end of a rendezvous rather than a failure to report.
        if (refusal instanceof RendezvousGone) return { status: 'gone' };
        throw refusal;
      }
      return readState(body as StatusBody);
    },

    async abandon(requestId) {
      try {
        await request(
          base,
          'DELETE',
          `/device-approval/requests/${pathId(requestId)}`,
          accessToken
        );
      } catch {
        // The row expires on its own, so a failed cancel strands nothing.
      }
    },
  };
}

/** The refusal a poll turns into `gone` rather than an error. */
class RendezvousGone extends Error {}

/**
 * An id the API minted, bound for a request path. Percent-encoding leaves a dot
 * segment intact, so the alphabet is checked rather than the escaping trusted.
 */
function pathId(requestId: string): string {
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(requestId) || requestId === '.' || requestId === '..') {
    throw new Error('the rendezvous answered with an id this build will not follow');
  }
  return requestId;
}

function readAccessToken(body: unknown): string {
  const minted = body as { accessToken?: unknown };
  if (typeof minted.accessToken !== 'string' || minted.accessToken === '') {
    throw new Error('no device on this account can approve this sign-in');
  }
  return minted.accessToken;
}

function readState(body: StatusBody): RendezvousState {
  switch (body.status) {
    case 'pending':
      return { status: 'pending', expiresAt: body.expiresAt };
    case 'denied':
      return { status: 'denied' };
    case 'approved':
      if (typeof body.sealedFactor !== 'string') throw new Error('the approval carried no factor');
      return { status: 'approved', sealedFactor: body.sealedFactor };
    default:
      throw new Error('the rendezvous answered with a state this build does not know');
  }
}

async function request(
  base: string,
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  bearer: string | null,
  options: { body?: unknown; goneOn404?: boolean } = {}
): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (bearer !== null) headers.authorization = `Bearer ${bearer}`;
  let response: Response;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new Error('CipherBox could not be reached — check your connection');
  }
  // Only a poll reads a 404 as the ordinary end of a rendezvous. On the mint it
  // means no device on the account can approve, which the member must be told.
  if (options.goneOn404 === true && response.status === 404) {
    throw new RendezvousGone('the rendezvous is gone');
  }
  if (!response.ok) throw new Error(await refusalOf(response));
  return response.status === 204 ? null : ((await response.json()) as unknown);
}

/**
 * The API's own refusal text, which is written for the member. Anything else
 * that answered — a proxy, an error page — is reported as a bare refusal.
 */
async function refusalOf(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    const message = (body as { message?: unknown }).message;
    if (typeof message === 'string') return message;
    if (Array.isArray(message) && typeof message[0] === 'string') return message[0];
  } catch {
    /* fall through to the status */
  }
  return `device approval failed (${response.status})`;
}
