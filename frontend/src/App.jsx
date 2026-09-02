import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Dashboard }      from './pages/Dashboard';
import { Upload }         from './pages/Upload';
import { AnalysisView }   from './pages/AnalysisView';
import { Login }          from './pages/Login';
import { ThreatMemory }   from './pages/ThreatMemory';
import { Investigations } from './pages/Investigations';
import { IOCSearch }      from './pages/IOCSearch';
import { Reports }        from './pages/Reports';
import { Settings }       from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />

        {/* Protected Routes (Mocked for now) */}
        <Route element={<Layout />}>
          <Route path="/"               element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"      element={<Dashboard />} />
          <Route path="/upload"         element={<Upload />} />
          <Route path="/analysis/:id"   element={<AnalysisView />} />
          <Route path="/threats"        element={<ThreatMemory />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/ioc-search"     element={<IOCSearch />} />
          <Route path="/reports"        element={<Reports />} />
          <Route path="/settings"       element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
