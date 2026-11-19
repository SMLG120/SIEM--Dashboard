import { lazy, Suspense, useCallback, useEffect, useState, type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { LogIn, RefreshCw, Shield, ShieldOff } from "lucide-react";
import { initializeAuth, login, type AuthState } from "./auth";
import { AppLayout } from "./layout";

// Route-level code splitting: charts and heavier pages load on first visit.
const DashboardPage = lazy(() => import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const EventsPage = lazy(() => import("./pages/EventsPage").then((m) => ({ default: m.EventsPage })));
const AlertsPage = lazy(() => import("./pages/AlertsPage").then((m) => ({ default: m.AlertsPage })));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage").then((m) => ({ default: m.IncidentsPage })));
const IncidentDetailPage = lazy(() =>
  import("./pages/IncidentDetailPage").then((m) => ({ default: m.IncidentDetailPage }))
);
const RulesPage = lazy(() => import("./pages/RulesPage").then((m) => ({ default: m.RulesPage })));
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntelPage").then((m) => ({ default: m.ThreatIntelPage })));
const SearchPage = lazy(() => import("./pages/SearchPage").then((m) => ({ default: m.SearchPage })));
const PlatformPage = lazy(() => import("./pages/PlatformPage").then((m) => ({ default: m.PlatformPage })));

const initialAuthState: AuthState = {
  initialized: false,
  authenticated: false,
  displayName: "",
  username: "",
  roles: []
};

export default function App() {
  const [auth, setAuth] = useState<AuthState>(initialAuthState);
  const [authError, setAuthError] = useState<string>();

  const start = useCallback(() => {
    setAuthError(undefined);
    initializeAuth()
      .then(setAuth)
      .catch((error: Error) => setAuthError(error.message));
  }, []);

  useEffect(start, [start]);

  if (authError) {
    return (
      <main className="auth-screen">
        <div className="auth-panel" role="alert">
          <ShieldOff size={38} />
          <h1>Sign-in unavailable</h1>
          <p className="auth-hint">{authError} The console needs the identity provider to load.</p>
          <button type="button" className="primary-action" onClick={start}>
            <RefreshCw size={18} />
            Retry
          </button>
        </div>
      </main>
    );
  }

  if (!auth.initialized) {
    return (
      <main className="auth-screen">
        <Shield size={34} />
        <h1>Enterprise SIEM</h1>
        <p className="auth-hint" aria-live="polite">Connecting to the sign-in service…</p>
      </main>
    );
  }

  if (!auth.authenticated) {
    return (
      <main className="auth-screen">
        <div className="auth-panel">
          <Shield size={38} />
          <h1>Enterprise SIEM</h1>
          <p className="auth-hint">Security operations console · sign in with your SOC account</p>
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
          <Route index element={<Lazy><DashboardPage /></Lazy>} />
          <Route path="events" element={<Lazy><EventsPage auth={auth} /></Lazy>} />
          <Route path="alerts" element={<Lazy><AlertsPage auth={auth} /></Lazy>} />
          <Route path="incidents" element={<Lazy><IncidentsPage auth={auth} /></Lazy>} />
          <Route path="incidents/:incidentId" element={<Lazy><IncidentDetailPage auth={auth} /></Lazy>} />
          <Route path="rules" element={<Lazy><RulesPage auth={auth} /></Lazy>} />
          <Route path="threat-intel" element={<Lazy><ThreatIntelPage auth={auth} /></Lazy>} />
          <Route path="intelligence" element={<Navigate to="/rules" replace />} />
          <Route path="search" element={<Lazy><SearchPage /></Lazy>} />
          <Route path="platform" element={<Lazy><PlatformPage auth={auth} /></Lazy>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<div className="empty-state" aria-busy="true">Loading…</div>}>{children}</Suspense>;
}
