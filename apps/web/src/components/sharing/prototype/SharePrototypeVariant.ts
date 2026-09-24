/** PROTOTYPE — throwaway. Which share-dialog variant `?variant=` asks for. */
import { useSearchParams } from 'react-router-dom';

export const PROTO_VARIANTS = [
  { key: 'A', name: 'link first' },
  { key: 'B', name: 'people first' },
  { key: 'C', name: 'steps' },
  { key: 'D', name: 'people table + inline link' },
] as const;

export type ProtoVariant = (typeof PROTO_VARIANTS)[number]['key'];

/** `null` when the param is absent or unknown, and always in a production build. */
export function useSharePrototypeVariant(): ProtoVariant | null {
  const [params] = useSearchParams();
  if (import.meta.env.PROD) return null;
  const raw = params.get('variant')?.toUpperCase();
  return PROTO_VARIANTS.find((variant) => variant.key === raw)?.key ?? null;
}
