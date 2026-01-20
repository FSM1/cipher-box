import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './Login';
import { Dashboard } from './Dashboard';

export function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
