import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './Login';
import { FilesPage } from './FilesPage';
import { SharedPage } from './SharedPage';
import { BinPage } from './BinPage';
import { SettingsPage } from './SettingsPage';
import { InvitePage } from './InvitePage';

export function AppRoutes() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/invite/:token" element={<InvitePage />} />
        <Route path="/files/:folderId?" element={<FilesPage />} />
        <Route path="/shared" element={<SharedPage />} />
        <Route path="/bin" element={<BinPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/dashboard" element={<Navigate to="/files" replace />} />
      </Routes>
    </HashRouter>
  );
}
