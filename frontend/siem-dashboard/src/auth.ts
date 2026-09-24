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

const keycloakUrl = import.meta.env.VITE_KEYCLOAK_URL ?? "http://localhost:8088";
const keycloakRealm = import.meta.env.VITE_KEYCLOAK_REALM ?? "enterprise-siem";
const keycloakClientId = import.meta.env.VITE_KEYCLOAK_CLIENT_ID ?? "siem-dashboard";

export const keycloak = new Keycloak({
  url: keycloakUrl,
  realm: keycloakRealm,
  clientId: keycloakClientId
});

let initPromise: Promise<AuthState> | undefined;

export function initializeAuth(): Promise<AuthState> {
  initPromise ??= keycloak
    .init({
      onLoad: "check-sso",
      pkceMethod: "S256",
      checkLoginIframe: false
    })
    .then(() => currentAuthState());
  return initPromise;
}

export async function getAccessToken(): Promise<string | undefined> {
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

