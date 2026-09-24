import { useEffect, useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { LogIn, Shield } from "lucide-react";
import { currentAuthState, initializeAuth, login, type AuthState } from "./auth";
import { AppLayout } from "./layout";
import { AlertsPage } from "./pages/AlertsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { EventsPage } from "./pages/EventsPage";
import { IncidentDetailPage } from "./pages/IncidentDetailPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { IntelligencePage } from "./pages/IntelligencePage";
import { PlatformPage } from "./pages/PlatformPage";

const initialAuthState: AuthState = {
  initialized: false,
  authenticated: false,
  displayName: "",
  username: "",
  roles: []
};

export default function App() {
  const [auth, setAuth] = useState<AuthState>(initialAuthState);

  useEffect(() => {
    initializeAuth().then(() => setAuth(currentAuthState()));
  }, []);

  if (!auth.initialized) {
    return (
      <main className="auth-screen">
        <Shield size={34} />
        <h1>Enterprise SIEM</h1>
      </main>
    );
  }

  if (!auth.authenticated) {
    return (
      <main className="auth-screen">
        <div className="auth-panel">
          <Shield size={38} />
          <h1>Enterprise SIEM</h1>
          <p className="auth-hint">Sign in with a realm account (e.g. admin / admin123)</p>
          <button type="button" className="primary-action" onClick={() => void login()}>
            <LogIn size={18} />
            Sign In
          </button>
        </div>
      </main>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout auth={auth} />}>
          <Route index element={<DashboardPage />} />
          <Route path="events" element={<EventsPage auth={auth} />} />
          <Route path="alerts" element={<AlertsPage auth={auth} />} />
          <Route path="incidents" element={<IncidentsPage auth={auth} />} />
          <Route path="incidents/:incidentId" element={<IncidentDetailPage auth={auth} />} />
          <Route path="intelligence" element={<IntelligencePage auth={auth} />} />
          <Route path="platform" element={<PlatformPage />} />
          <Route path="*" element={<DashboardPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}