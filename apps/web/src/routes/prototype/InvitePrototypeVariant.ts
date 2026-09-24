/** PROTOTYPE — throwaway. Which invite-page variant `?variant=` asks for. */
import { useSearchParams } from 'react-router-dom';

export const INVITE_PROTO_VARIANTS = [
  { key: 'A', name: 'stacked card' },
  { key: 'B', name: 'two panes' },
  { key: 'C', name: 'steps' },
] as const;

export type InviteProtoVariant = (typeof INVITE_PROTO_VARIANTS)[number]['key'];

/** `null` when the param is absent or unknown, and always in a production build. */
export function useInvitePrototypeVariant(): InviteProtoVariant | null {
  const [params] = useSearchParams();
  if (import.meta.env.PROD) return null;
  const raw = params.get('variant')?.toUpperCase();
  return INVITE_PROTO_VARIANTS.find((variant) => variant.key === raw)?.key ?? null;
}
