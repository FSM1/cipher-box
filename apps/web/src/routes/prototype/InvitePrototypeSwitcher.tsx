/** PROTOTYPE — throwaway. The floating variant switcher bar. */
import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Portal } from '../../components/ui/Portal';
import { INVITE_PROTO_VARIANTS, type InviteProtoVariant } from './InvitePrototypeVariant';

export function InvitePrototypeSwitcher({ current }: { current: InviteProtoVariant }) {
  const [, setParams] = useSearchParams();
  const index = INVITE_PROTO_VARIANTS.findIndex((variant) => variant.key === current);

  const step = useCallback(
    (delta: number) => {
      const count = INVITE_PROTO_VARIANTS.length;
      const next = INVITE_PROTO_VARIANTS[(index + delta + count) % count];
      setParams(
        (prev) => {
          const params = new URLSearchParams(prev);
          params.set('variant', next.key);
          return params;
        },
        { replace: true }
      );
    },
    [index, setParams]
  );

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      const target = event.target as HTMLElement | null;
      if (
        target?.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"]')
      )
        return;
      event.preventDefault();
      step(event.key === 'ArrowLeft' ? -1 : 1);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [step]);

  if (import.meta.env.PROD) return null;

  return (
    <Portal>
      <div className="proto-inv-switcher" data-testid="proto-switcher">
        <button type="button" aria-label="previous variant" onClick={() => step(-1)}>
          ←
        </button>
        <span className="proto-inv-switcher-label">
          {current} ({INVITE_PROTO_VARIANTS[index].name})
        </span>
        <button type="button" aria-label="next variant" onClick={() => step(1)}>
          →
        </button>
      </div>
    </Portal>
  );
}
