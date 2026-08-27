import { errorMessage } from '../../lib/errorMessage';

/** Renders a wallet refusal as a refusal rather than as a raw provider dump. */
export function rejectionOf(failure: unknown): string {
  const text = errorMessage(failure);
  return /user rejected|ACTION_REJECTED/i.test(text) ? 'the wallet request was rejected' : text;
}
