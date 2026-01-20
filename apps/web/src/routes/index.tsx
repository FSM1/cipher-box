import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Login } from './Login';
import { Dashboard } from './Dashboard';
import { Settings } from './Settings';

export function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </BrowserRouter>
  );
}
