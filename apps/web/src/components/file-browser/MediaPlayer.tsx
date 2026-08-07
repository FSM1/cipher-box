/**
 * Playback over a stream ticket. A body the pipe errors reaches the element as
 * an untyped network failure, so the reason comes from the engine code the
 * media service reports, not from the element's own `error` event.
 */

import { useEffect, useState } from 'react';
import type { MediaStreamFailure } from '@cipherbox/client';
import { useMediaService } from '../../providers/EngineProvider';

interface MediaPlayerProps {
  url: string;
  kind: 'audio' | 'video';
  name: string;
}

/**
 * What the player has to say about a stream that stopped. `recoverable` is a
 * ceiling the engine expects a later read to clear, so it carries a retry.
 */
type Refusal = { kind: 'recoverable' | 'fault'; message: string };

const CEILING_NOTICE = 'too many streams are open right now';

const FAULT_NOTICE = 'playback failed';

export function MediaPlayer({ url, kind, name }: MediaPlayerProps) {
  const media = useMediaService();
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  // A retry remounts the element rather than reusing one the browser has given
  // up on. The ticket is still live: the pipe refused a read, it did not
  // withdraw the capability.
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (media === null) return;
    return media.onStreamError((failure: MediaStreamFailure) => {
      if (failure.url !== url) return;
      setRefusal(
        failure.recoverable
          ? { kind: 'recoverable', message: CEILING_NOTICE }
          : { kind: 'fault', message: failure.message }
      );
    });
  }, [media, url]);

  const props = {
    className: `media-player-${kind}`,
    src: url,
    controls: true,
    preload: 'metadata' as const,
    'aria-label': name,
    'data-testid': `media-player-${kind}`,
    // The element reports a failure the pipe never named — an unsupported
    // container, a decode refusal — with no code to classify it by.
    onError: () => setRefusal((held) => held ?? { kind: 'fault', message: FAULT_NOTICE }),
  };

  return (
    <div className="media-player" data-testid="media-player">
      {kind === 'video' ? <video key={attempt} {...props} /> : <audio key={attempt} {...props} />}
      {refusal !== null && (
        <p
          className={`media-player-notice media-player-notice--${refusal.kind}`}
          role="alert"
          data-testid="media-player-error"
        >
          {refusal.message}
          {refusal.kind === 'recoverable' && (
            <button
              type="button"
              className="dialog-button"
              onClick={() => {
                setRefusal(null);
                setAttempt((run) => run + 1);
              }}
              data-testid="media-player-retry"
            >
              retry
            </button>
          )}
        </p>
      )}
    </div>
  );
}
