/** PROTOTYPE — throwaway. The floating variant switcher bar. */
import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Portal } from '../../ui/Portal';
import { PROTO_VARIANTS, type ProtoVariant } from './SharePrototypeVariant';
import './SharePrototype.css';

export function SharePrototypeSwitcher({ current }: { current: ProtoVariant }) {
  const [, setParams] = useSearchParams();
  const index = PROTO_VARIANTS.findIndex((variant) => variant.key === current);

  const step = useCallback(
    (delta: number) => {
      const next = PROTO_VARIANTS[(index + delta + PROTO_VARIANTS.length) % PROTO_VARIANTS.length];
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
      <div className="proto-switcher" data-testid="proto-switcher">
        <button type="button" aria-label="previous variant" onClick={() => step(-1)}>
          ←
        </button>
        <span className="proto-switcher-label">
          {current} ({PROTO_VARIANTS[index].name})
        </span>
        <button type="button" aria-label="next variant" onClick={() => step(1)}>
          →
        </button>
      </div>
    </Portal>
  );
}
