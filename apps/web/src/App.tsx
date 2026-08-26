import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth } from './auth/RequireAuth';
import { SessionEndWatcher } from './auth/SessionEndWatcher';
import { FilesPage } from './routes/FilesPage';
import { InvitePage } from './routes/InvitePage';
import { LoginPage } from './routes/LoginPage';
import { SettingsPage } from './routes/SettingsPage';
import { INVITE_ROUTE } from './sharing/inviteLink';

export function App() {
  return (
    <>
      <SessionEndWatcher />
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route
          path="/files/:nodeId?"
          element={
            <RequireAuth>
              <FilesPage />
            </RequireAuth>
          }
        />
        <Route
          path="/settings"
          element={
            <RequireAuth>
              <SettingsPage />
            </RequireAuth>
          }
        />
        {/* No `RequireAuth`: a redirect would drop the fragment the link is. */}
        <Route path={INVITE_ROUTE} element={<InvitePage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
