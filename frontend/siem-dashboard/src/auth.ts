import Keycloak from "keycloak-js";

type TokenClaims = {
  name?: string;
  preferred_username?: string;
  realm_access?: {
    roles?: string[];
  };
};

export type AuthState = {
  initialized: boolean;
  authenticated: boolean;
  displayName: string;
  username: string;
  roles: string[];
  token?: string;
};

const keycloakUrl = import.meta.env.VITE_KEYCLOAK_URL ?? "http://localhost:18088";
const keycloakRealm = import.meta.env.VITE_KEYCLOAK_REALM ?? "enterprise-siem";
const keycloakClientId = import.meta.env.VITE_KEYCLOAK_CLIENT_ID ?? "siem-dashboard";

export const keycloak = new Keycloak({
  url: keycloakUrl,
  realm: keycloakRealm,
  clientId: keycloakClientId
});

/**
 * End-to-end test builds (`vite build --mode e2e`) use a fixed identity so Playwright can drive every
 * role without a live Keycloak. MODE is a compile-time constant, so production builds drop this code.
 */
const E2E = import.meta.env.MODE === "e2e";

function e2eState(): AuthState {
  let roles = ["SECURITY_ANALYST"];
  try {
    roles = JSON.parse(window.localStorage.getItem("siem.e2e.roles") ?? "null") ?? roles;
  } catch {
    // default roles
  }
  return { initialized: true, authenticated: true, displayName: "E2E Analyst", username: "e2e.analyst", roles };
}

const INIT_TIMEOUT_MS = 15_000;

let initPromise: Promise<AuthState> | undefined;

/**
 * Rejects if the identity provider can't be reached (or doesn't answer within 15 s), so the UI can
 * show an error with a retry instead of a splash screen that never ends.
 */
export function initializeAuth(): Promise<AuthState> {
  if (E2E) {
    return Promise.resolve(e2eState());
  }
  initPromise ??= Promise.race([
    keycloak.init({ onLoad: "check-sso", pkceMethod: "S256", checkLoginIframe: false }),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("The sign-in service did not respond in time.")), INIT_TIMEOUT_MS)
    )
  ])
    .then(() => currentAuthState())
    .catch((error: unknown) => {
      initPromise = undefined; // allow retry
      throw error instanceof Error ? error : new Error("The sign-in service is unavailable.");
    });
  return initPromise;
}

export async function getAccessToken(): Promise<string | undefined> {
  if (E2E) {
    return "e2e-token";
  }
  if (!keycloak.authenticated) {
    return undefined;
  }
  await keycloak.updateToken(30);
  return keycloak.token;
}

export function login() {
  return keycloak.login({ redirectUri: window.location.origin });
}

export function logout() {
  return keycloak.logout({ redirectUri: window.location.origin });
}

export function currentAuthState(): AuthState {
  if (E2E) {
    return e2eState();
  }
  const claims = keycloak.tokenParsed as TokenClaims | undefined;
  const username = claims?.preferred_username ?? "";
  const roles = claims?.realm_access?.roles ?? [];

  return {
    initialized: true,
    authenticated: Boolean(keycloak.authenticated),
    displayName: claims?.name ?? username,
    username,
    roles,
    token: keycloak.token
  };
}

