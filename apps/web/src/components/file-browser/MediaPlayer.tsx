import { useLayoutEffect, useState } from 'react';
import type { MediaStreamFailure } from '@cipherbox/client';
import { useMediaService } from '../../providers/EngineProvider';

interface MediaPlayerProps {
  url: string;
  kind: 'audio' | 'video';
  name: string;
}

type Refusal = { recoverable: boolean; message: string };

const CEILING_NOTICE = 'too many streams are open right now';

const FAULT_NOTICE = 'playback failed';

/** Playback over a stream ticket, with what stopped it when something does. */
export function MediaPlayer({ url, kind, name }: MediaPlayerProps) {
  const media = useMediaService();
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  // The browser will not re-read a src it has given up on; only a remount will.
  const [attempt, setAttempt] = useState(0);

  // Subscribed in the commit that mounts the element: the pipe replays nothing,
  // so a refusal reported before this runs is lost.
  useLayoutEffect(() => {
    if (media === null) return;
    return media.onStreamError((failure: MediaStreamFailure) => {
      if (failure.url !== url) return;
      setRefusal({
        recoverable: failure.recoverable,
        message: failure.recoverable ? CEILING_NOTICE : failure.message,
      });
    });
  }, [media, url]);

  const props = {
    className: `media-player-${kind}`,
    src: url,
    controls: true,
    preload: 'metadata' as const,
    'aria-label': name,
    'data-testid': `media-player-${kind}`,
    // A named reason from the pipe outranks the element's unclassifiable one.
    onError: () => setRefusal((held) => held ?? { recoverable: false, message: FAULT_NOTICE }),
  };

  return (
    <div className="media-player" data-testid="media-player">
      {kind === 'video' ? <video key={attempt} {...props} /> : <audio key={attempt} {...props} />}
      {refusal?.recoverable === true && (
        <div className="file-browser-notice" role="status" data-testid="media-player-error">
          <span className="file-browser-notice-message">{refusal.message}</span>
          <button
            type="button"
            className="file-browser-notice-retry"
            onClick={() => {
              setRefusal(null);
              setAttempt((run) => run + 1);
            }}
            data-testid="media-player-retry"
          >
            [retry]
          </button>
        </div>
      )}
      {refusal?.recoverable === false && (
        <p
          className="preview-status preview-status--error"
          role="alert"
          data-testid="media-player-error"
        >
          {refusal.message}
        </p>
      )}
    </div>
  );
}
