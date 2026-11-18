import { Activity, Crosshair, Database, Globe2, LogOut, RadioTower, Search, Shield, ShieldAlert, Siren, UserRound } from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { logout, type AuthState } from "./auth";

const pageTitles: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Command Overview", subtitle: "Security Operations Center" },
  "/events": { title: "Live Events", subtitle: "Ingestion stream and query" },
  "/alerts": { title: "Alerts", subtitle: "Triage queue with detection evidence" },
  "/incidents": { title: "Incident Investigation", subtitle: "Correlated alerts, timeline and notes" },
  "/rules": { title: "Detection Rules", subtitle: "Catalogue, MITRE ATT&CK coverage and rule testing" },
  "/threat-intel": { title: "Threat Intel", subtitle: "Curated indicators and sightings" },
  "/search": { title: "Search", subtitle: "Indexed event and alert search" },
  "/platform": { title: "Platform Health", subtitle: "Services, pipeline and audit trail" }
};

export function AppLayout({ auth }: { auth: AuthState }) {
  const location = useLocation();
  const titleKey = location.pathname.startsWith("/incidents") ? "/incidents" : location.pathname;
  const heading = pageTitles[titleKey] ?? pageTitles["/"];

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <Shield size={26} />
          <span>Enterprise SIEM</span>
        </div>
        <nav>
          <NavLink to="/" end>
            <Activity size={18} /> Overview
          </NavLink>
          <NavLink to="/events">
            <RadioTower size={18} /> Live Events
          </NavLink>
          <NavLink to="/alerts">
            <Siren size={18} /> Alerts
          </NavLink>
          <NavLink to="/incidents">
            <ShieldAlert size={18} /> Incidents
          </NavLink>
          <NavLink to="/rules">
            <Crosshair size={18} /> Detection Rules
          </NavLink>
          <NavLink to="/threat-intel">
            <Globe2 size={18} /> Threat Intel
          </NavLink>
          <NavLink to="/search">
            <Search size={18} /> Search
          </NavLink>
          <NavLink to="/platform">
            <Database size={18} /> Platform Health
          </NavLink>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p>{heading.subtitle}</p>
            <h1>{heading.title}</h1>
          </div>
          <div className="identity-cluster">
            <div className="role-strip" aria-label="Assigned roles">
              {auth.roles
                .filter(
                  (role) =>
                    role.startsWith("ADMIN") ||
                    role.startsWith("SOC_") ||
                    role.startsWith("SECURITY_") ||
                    role === "VIEWER"
                )
                .map((role) => (
                  <span key={role}>{role}</span>
                ))}
            </div>
            <button type="button" className="analyst-button" aria-label="Current analyst">
              <UserRound size={18} />
              {auth.displayName || auth.username}
            </button>
            <button
              type="button"
              className="icon-button"
              onClick={() => void logout()}
              aria-label="Sign out"
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>

        <Outlet />
      </section>
    </main>
  );
}