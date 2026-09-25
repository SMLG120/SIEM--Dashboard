import { getAccessToken } from "./auth";

export type EventSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type SecurityEvent = {
  id: string;
  timestamp: string;
  eventType: string;
  severity: EventSeverity;
  category?: string;
  sourceIp?: string;
  sourceHost?: string;
  destinationIp?: string;
  destinationPort?: number;
  userName?: string;
  message?: string;
};

export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED";

export type SiemAlert = {
  id: string;
  createdAt: string;
  ruleId: string;
  ruleName: string;
  description: string;
  severity: EventSeverity;
  eventType: string;
  eventId: string;
  sourceIp?: string;
  userName?: string;
  status: AlertStatus;
};

export type AlertNote = {
  id: string;
  author: string;
  text: string;
  createdAt: string;
};

export type AlertDetail = {
  alert: SiemAlert;
  assignedTo?: string;
  notes: AlertNote[];
};

export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";

export type RelatedAlert = {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: EventSeverity;
  eventType: string;
  sourceIp?: string;
  description?: string;
  createdAt: string;
};

export type TimelineEntry = {
  occurredAt: string;
  actor: string;
  action: string;
  detail?: string;
};

export type IncidentNote = {
  id: string;
  author: string;
  text: string;
  createdAt: string;
};

export type Incident = {
  id: string;
  title: string;
  description?: string;
  severity: EventSeverity;
  status: IncidentStatus;
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
  relatedAlerts: RelatedAlert[];
  timeline: TimelineEntry[];
  notes: IncidentNote[];
};

export type DetectionRule = {
  id: string;
  name: string;
  description?: string;
  severity: EventSeverity;
  enabled: boolean;
  condition: {
    eventTypes?: string[];
    category?: string;
    severityMin?: string;
  };
};

export type DetectionSummary = {
  eventsEvaluated: number;
  alertsGenerated: number;
  rulesEnabled: number;
  recentAlerts: SiemAlert[];
};

export type SearchHit = {
  index: string;
  id: string;
  timestamp?: string;
  fields: Record<string, unknown>;
};

export type SearchSummary = {
  eventsCount: number;
  alertsCount: number;
  eventsBySeverity: Record<string, number>;
  alertsBySeverity: Record<string, number>;
};

export type ServiceStatus = {
  service: string;
  role: string;
  phase: string;
  status: string;
  timestamp: string;
};

export type IngestEventInput = {
  eventType: string;
  severity: EventSeverity;
  category?: string;
  sourceIp?: string;
  sourceHost?: string;
  destinationIp?: string;
  destinationPort?: number;
  userName?: string;
  message?: string;
};

export type CreateIncidentInput = {
  title: string;
  description?: string;
  severity: EventSeverity;
};

export type UpdateIncidentInput = {
  title?: string;
  description?: string;
  severity?: EventSeverity;
  status?: IncidentStatus;
  assignedTo?: string;
};

export type LinkAlertInput = {
  alertId: string;
  ruleId?: string;
  ruleName?: string;
  eventType?: string;
  severity?: EventSeverity;
  sourceIp?: string;
  description?: string;
};

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

async function authenticatedHeaders(): Promise<Record<string, string>> {
  const token = await getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function sendJson<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers = {
    "Content-Type": "application/json",
    ...(await authenticatedHeaders())
  };
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`${method} ${path} failed: HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function apiGet<T>(path: string): Promise<T> {
  return sendJson<T>("GET", path);
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return sendJson<T>("POST", path, body);
}

export async function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  return sendJson<T>("PATCH", path, body);
}

export async function fetchServiceStatus(path: string): Promise<ServiceStatus | null> {
  try {
    return await apiGet<ServiceStatus>(path);
  } catch {
    return null;
  }
}

export const serviceEndpoints = [
  { label: "Auth", path: "/api/auth/internal/status", key: "auth" },
  { label: "Ingestion", path: "/api/events/internal/status", key: "ingestion" },
  { label: "Detection", path: "/api/detection/internal/status", key: "detection" },
  { label: "Alerts", path: "/api/alerts/internal/status", key: "alerts" },
  { label: "Incidents", path: "/api/incidents/internal/status", key: "incidents" },
  { label: "Search", path: "/api/search/internal/status", key: "search" },
  { label: "Threat Intel", path: "/api/threat-intel/internal/status", key: "threat-intel" },
  { label: "Audit", path: "/api/audit/internal/status", key: "audit" }
] as const;

export const commonEventTypes = [
  "LOGIN_FAILURE",
  "LOGIN_SUCCESS",
  "MALWARE_DETECTED",
  "RANSOMWARE_ACTIVITY",
  "PRIVILEGE_ESCALATION",
  "PORT_SCAN",
  "DATA_EXFILTRATION",
  "COMMAND_SHELL",
  "WEBSHELL",
  "C2_BEACON",
  "TOR_UNKNOWN",
  "CONFIG_CHANGE",
  "PATCH_APPLIED"
];

export const eventSeverities: EventSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const incidentStatuses: IncidentStatus[] = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];