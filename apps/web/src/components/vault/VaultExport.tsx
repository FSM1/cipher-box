import { useState } from 'react';
import { vaultControllerExportVault } from '../../api/vault/vault';
import { ConfirmDialog } from '../file-browser/ConfirmDialog';
import './vault-export.css';

/**
 * VaultExport component for the Settings page.
 *
 * Provides a button to export vault data as JSON for independent recovery.
 * Shows a security confirmation dialog before exporting.
 */
export function VaultExport() {
  const [showDialog, setShowDialog] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async () => {
    setIsExporting(true);
    setError(null);

    try {
      const data = await vaultControllerExportVault();

      // Trigger browser download
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);

      const link = document.createElement('a');
      link.href = url;
      link.download = 'cipherbox-vault-export.json';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      URL.revokeObjectURL(url);
      setShowDialog(false);
    } catch {
      setError('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="vault-export">
      <h3 className="vault-export__title">[VAULT EXPORT]</h3>
      <p className="vault-export__description">
        Download your vault data for independent recovery. The export contains encrypted keys that
        can reconstruct your entire file tree.
      </p>

      <button
        type="button"
        className="vault-export__button"
        onClick={() => {
          setError(null);
          setShowDialog(true);
        }}
      >
        --export vault
      </button>

      {error && (
        <p className="vault-export__error" role="alert">
          {error}
        </p>
      )}

      <ConfirmDialog
        open={showDialog}
        onClose={() => setShowDialog(false)}
        onConfirm={handleExport}
        title="export vault"
        message="This export contains encrypted keys for your entire vault. Anyone with this file AND your private key can access all your files. Store it securely -- external drive, password manager, or printed paper backup."
        confirmLabel="CONFIRM EXPORT"
        isDestructive={false}
        isLoading={isExporting}
      />
    </div>
  );
}
