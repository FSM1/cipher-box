import { Link } from 'react-router-dom';

export function Dashboard() {
  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1>My Vault</h1>
        <Link to="/login" className="logout-link">Logout</Link>
      </header>
      <main className="dashboard-main">
        <aside className="folder-sidebar">
          <h2>Folders</h2>
          <p className="placeholder-text">Folder tree (Phase 5)</p>
        </aside>
        <section className="file-browser">
          <h2>Files</h2>
          <p className="placeholder-text">File browser (Phase 6)</p>
        </section>
      </main>
    </div>
  );
}
