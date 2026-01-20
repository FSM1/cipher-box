import { useCallback, useState } from 'react';
import { deleteFile, deleteFiles } from '../services/delete.service';

export function useFileDelete() {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const deleteSingle = useCallback(async (cid: string, sizeBytes: number): Promise<void> => {
    setIsDeleting(true);
    setError(null);

    try {
      await deleteFile(cid, sizeBytes);
    } catch (err) {
      const message = (err as Error).message || 'Delete failed';
      setError(message);
      throw err;
    } finally {
      setIsDeleting(false);
    }
  }, []);

  const deleteMultiple = useCallback(
    async (
      files: Array<{ cid: string; size: number }>
    ): Promise<{ succeeded: string[]; failed: string[] }> => {
      setIsDeleting(true);
      setError(null);

      try {
        const result = await deleteFiles(files);
        if (result.failed.length > 0) {
          setError(`Failed to delete ${result.failed.length} file(s)`);
        }
        return result;
      } finally {
        setIsDeleting(false);
      }
    },
    []
  );

  return {
    isDeleting,
    error,
    deleteFile: deleteSingle,
    deleteFiles: deleteMultiple,
    clearError: () => setError(null),
  };
}
