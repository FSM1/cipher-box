/**
 * Saving one file to disk: the facade's verified read, handed to the browser as
 * an opaque blob. The bytes are plaintext, so the object URL is revoked as soon
 * as the download has started.
 */

import { useCallback, useState } from 'react';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Never a renderable type: a blob URL is same-origin with the app. */
const OPAQUE = 'application/octet-stream';

export interface FileDownload {
  saving: boolean;
  error: string | null;
  save(node: Uint8Array, name: string): Promise<void>;
}

export function useFileDownload(): FileDownload {
  const client = useEngine();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = useCallback(
    async (node: Uint8Array, name: string): Promise<void> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return;
      }
      setSaving(true);
      setError(null);
      try {
        const bytes = await client.facade.download(node);
        saveToDisk(new Blob([bytes], { type: OPAQUE }), name);
      } catch (failure: unknown) {
        setError(errorMessage(failure));
      } finally {
        setSaving(false);
      }
    },
    [client]
  );

  return { saving, error, save };
}

function saveToDisk(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
