import { Navigate, Route, Routes } from 'react-router-dom';
import { FilesPage } from './routes/FilesPage';
import { LoginPage } from './routes/LoginPage';

export function App() {
  return (
    <Routes>
      <Route path="/" element={<LoginPage />} />
      <Route path="/files/:nodeId?" element={<FilesPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
