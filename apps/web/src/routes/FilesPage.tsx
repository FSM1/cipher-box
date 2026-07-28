import { useParams } from 'react-router-dom';

/** Placeholder for the vault browser (#805). */
export function FilesPage() {
  // Routes key on the stable node id; an absent id is the vault's current root
  // (blueprint/web-client.md "UI state law").
  const { nodeId } = useParams<{ nodeId: string }>();
  return (
    <main>
      <h1>Files</h1>
      <p data-testid="files-node">{nodeId ?? 'root'}</p>
    </main>
  );
}
