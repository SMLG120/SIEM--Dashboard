import { test as base, type Page, type Route } from "@playwright/test";

export const API = "http://localhost:18080";

const now = "2026-11-18T10:00:00Z";

export const bruteForceRule = {
  id: "SIEM-1008",
  version: 1,
  name: "Brute force from single source",
  description: "Many failed logins from one source IP in a short window.",
  severity: "HIGH",
  enabled: true,
  type: "THRESHOLD",
  condition: { eventTypes: ["LOGIN_FAILURE"] },
  threshold: { groupBy: ["sourceIp"], windowSeconds: 300, count: 10 },
  suppressionSeconds: 900,
  mitre: [{ tactic: "Credential Access", techniqueId: "T1110.001", technique: "Password Guessing" }],
  falsePositives: ["A user repeatedly typing an expired password"],
  examples: {
    match: [{ eventType: "LOGIN_FAILURE", severity: "LOW", sourceIp: "198.51.100.7" }],
    noMatch: [{ eventType: "LOGIN_SUCCESS", severity: "INFO", sourceIp: "198.51.100.7" }]
  }
};

export const powershellRule = {
  ...bruteForceRule,
  id: "SIEM-1010",
  name: "Encoded PowerShell command",
  type: "SINGLE",
  severity: "HIGH",
  threshold: undefined,
  condition: { eventTypes: ["POWERSHELL", "PROCESS_CREATE"], messageContainsAny: ["-enc"] },
  mitre: [{ tactic: "Execution", techniqueId: "T1059.001", technique: "PowerShell" }]
};

export const evidence = {
  ruleType: "THRESHOLD",
  matchedConditions: ["eventType in [LOGIN_FAILURE]", "count = 10 >= 10 per sourceIp within 300s"],
  eventIds: ["evt-aaaaaaaa-1", "evt-aaaaaaaa-2"],
  eventCount: 10,
  groupKey: "sourceIp=198.51.100.7",
  windowSeconds: 300,
  firstSeen: "2026-11-18T09:58:00Z",
  lastSeen: now
};

export const alert = {
  id: "alert-0001",
  createdAt: now,
  ruleId: "SIEM-1008",
  ruleVersion: 1,
  ruleName: "Brute force from single source",
  description: "10 failed logins from 198.51.100.7 in 300s",
  severity: "HIGH",
  eventType: "LOGIN_FAILURE",
  eventId: "evt-aaaaaaaa-2",
  sourceIp: "198.51.100.7",
  userName: "alice",
  status: "OPEN",
  mitre: bruteForceRule.mitre,
  evidence
};

type Handler = (route: Route, url: URL) => unknown;

/** Default API responses; tests override individual paths with mockApi(). */
export function defaultRoutes(): Record<string, Handler> {
  const json = (body: unknown, status = 200) => (route: Route) =>
    route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
  return {
    "GET /api/events": json([]),
    "GET /api/alerts": json([alert]),
    "GET /api/alerts/search": json({ items: [alert], total: 1, page: 0, size: 25 }),
    "GET /api/alerts/summary": json({
      total: 42,
      byStatus: { OPEN: 30, RESOLVED: 12 },
      openBySeverity: { CRITICAL: 3, HIGH: 7, MEDIUM: 11 },
      topRules: [{ ruleId: "SIEM-1008", ruleName: "Brute force from single source", alerts: 17 }]
    }),
    "GET /api/alerts/alert-0001/workflow": json({ alert, notes: [] }),
    "GET /api/alerts/alert-0001/history": json([
      { alertId: "alert-0001", action: "CREATED", toStatus: "OPEN", actor: "detection", occurredAt: now }
    ]),
    "POST /api/alerts/alert-0001/resolve": json({ ...alert, status: "RESOLVED" }),
    "GET /api/detection/summary": json({
      eventsEvaluated: 1200,
      alertsGenerated: 42,
      rulesEnabled: 18,
      rulesTotal: 18,
      alertsByRule: {},
      detectionLatencyMeanMs: 1.2,
      detectionLatencyP95Ms: 3.4,
      recentAlerts: [alert]
    }),
    "GET /api/rules": json([bruteForceRule, powershellRule]),
    "GET /api/rules/SIEM-1008/history": json([]),
    "GET /api/rules/SIEM-1010/history": json([]),
    "POST /api/rules/test": json({ ruleId: "SIEM-1008", ruleVersion: 1, ruleType: "THRESHOLD", alerts: [alert] }),
    "GET /api/incidents": json([]),
    "GET /api/threat-intel/indicators": json([
      {
        id: "ioc-1",
        type: "IP",
        value: "203.0.113.66",
        severity: "HIGH",
        description: "Simulated C2 server (RFC 5737 documentation range)",
        source: "SIMULATED_DEMO",
        createdBy: "demo-seed",
        createdAt: now,
        active: true
      }
    ]),
    "GET /api/threat-intel/sightings": json([
      {
        indicatorId: "ioc-1",
        type: "IP",
        value: "203.0.113.66",
        eventId: "evt-bbbbbbbb-1",
        field: "destinationIp",
        eventTime: now,
        recordedAt: now
      }
    ]),
    "GET /api/audit/events": json([
      {
        id: 1,
        occurredAt: now,
        actor: "sam.manager",
        action: "RULE_DISABLE",
        resourceType: "RULE",
        resourceId: "SIEM-1004",
        detail: "version=2"
      }
    ])
  };
}

export async function mockApi(page: Page, overrides: Record<string, Handler> = {}) {
  const routes = { ...defaultRoutes(), ...overrides };
  await page.route(`${API}/api/**`, async (route) => {
    const url = new URL(route.request().url());
    const key = `${route.request().method()} ${url.pathname}`;
    if (url.pathname.endsWith("/internal/status")) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ service: url.pathname, role: "x", phase: "v2", status: "READY", timestamp: now })
      });
    }
    const handler = routes[key];
    if (!handler) {
      return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ detail: `unmocked ${key}` }) });
    }
    return handler(route, url);
  });
}

export async function signInAs(page: Page, roles: string[]) {
  await page.addInitScript((r) => window.localStorage.setItem("siem.e2e.roles", JSON.stringify(r)), roles);
}

export const test = base;
export { expect } from "@playwright/test";
