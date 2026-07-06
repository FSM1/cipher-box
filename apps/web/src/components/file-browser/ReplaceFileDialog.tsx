import { useState, useCallback } from 'react';
import { Modal } from '../ui/Modal';
import { useUploadStore } from '../../stores/upload.store';
import type { PendingReplacement } from '../../stores/upload.store';
import { useFileOperations } from '../../hooks/useFileOperations';
import { getSdkClient } from '../../lib/sdk-provider';
import { useQuotaStore } from '../../stores/quota.store';
import '../../styles/dialogs.css';
import { logger } from '../../lib/logger';

type ReplaceFileDialogProps = {
  replacements: PendingReplacement[];
  onComplete: () => void;
};

/**
 * Dialog shown when uploaded files have names that already exist in the folder.
 * Offers Replace (creates version) or Skip (discards the upload) for each file.
 */
export function ReplaceFileDialog({ replacements, onComplete }: ReplaceFileDialogProps) {
  const { updateFile } = useFileOperations();
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(false);

  const current = replacements[currentIndex];
  const isLast = currentIndex >= replacements.length - 1;

  const advance = useCallback(() => {
    if (isLast) {
      useUploadStore.getState().clearPendingReplacements();
      onComplete();
    } else {
      setCurrentIndex((i) => i + 1);
    }
  }, [isLast, onComplete]);

  const handleReplace = useCallback(async () => {
    if (!current || isLoading) return;
    setIsLoading(true);
    try {
      await updateFile(current.parentId, {
        fileId: current.fileId,
        newCid: current.encryptedData.cid,
        newFileKeyEncrypted: current.encryptedData.wrappedKey,
        newFileIv: current.encryptedData.iv,
        newSize: current.encryptedData.size,
        newEncryptionMode: current.encryptedData.encryptionMode,
        forceVersion: true,
      });
      advance();
    } catch (err) {
      logger.error('[replace] Failed to replace file:', err);
      // Clean up orphaned pin + quota on failure
      void getSdkClient()
        .unpin(current.encryptedData.cid)
        .catch((err) => logger.warn('[replace] Unpin failed:', err));
      useQuotaStore.getState().removeUsage(current.encryptedData.size);
      advance();
    } finally {
      setIsLoading(false);
    }
  }, [current, isLoading, updateFile, advance]);

  const handleSkip = useCallback(() => {
    if (!current || isLoading) return;
    // Unpin the orphaned upload since user chose to skip
    void getSdkClient()
      .unpin(current.encryptedData.cid)
      .catch((err) => logger.warn('[replace] Unpin failed:', err));
    useQuotaStore.getState().removeUsage(current.encryptedData.size);
    advance();
  }, [current, isLoading, advance]);

  const handleClose = useCallback(() => {
    if (isLoading) return;
    // Skip all remaining replacements and clean up orphaned pins + quota
    for (let i = currentIndex; i < replacements.length; i++) {
      void getSdkClient()
        .unpin(replacements[i].encryptedData.cid)
        .catch((err) => logger.warn('[replace] Unpin failed:', err));
      useQuotaStore.getState().removeUsage(replacements[i].encryptedData.size);
    }
    useUploadStore.getState().clearPendingReplacements();
    onComplete();
  }, [isLoading, currentIndex, replacements, onComplete]);

  if (!current) return null;

  const remaining = replacements.length > 1 ? ` (${currentIndex + 1}/${replacements.length})` : '';

  return (
    <Modal open={true} onClose={handleClose} title={`Replace File${remaining}`}>
      <div className="dialog-content">
        <p className="dialog-message">
          {`A file named "${current.fileName}" already exists in this folder. Replace it? The current version will be saved in version history.`}
        </p>
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button dialog-button--secondary"
            onClick={handleSkip}
            disabled={isLoading}
          >
            Skip
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={handleReplace}
            disabled={isLoading}
            data-testid="replace-file-confirm"
          >
            {isLoading ? 'Replacing...' : 'Replace'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
