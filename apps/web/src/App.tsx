import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth } from './auth/RequireAuth';
import { FilesPage } from './routes/FilesPage';
import { InvitePage } from './routes/InvitePage';
import { LoginPage } from './routes/LoginPage';
import { INVITE_ROUTE } from './sharing/inviteLink';

export function App() {
  return (
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
      {/* No `RequireAuth`: a redirect would drop the fragment the link is. */}
      <Route path={INVITE_ROUTE} element={<InvitePage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
