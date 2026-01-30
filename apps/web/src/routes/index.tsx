import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './Login';
import { FilesPage } from './FilesPage';
import { SettingsPage } from './SettingsPage';

export function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/files/:folderId?" element={<FilesPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/dashboard" element={<Navigate to="/files" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
