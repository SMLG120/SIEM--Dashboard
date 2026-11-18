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
  schemaVersion?: number;
  attributes?: Record<string, string>;
};

export type MitreTechnique = {
  tactic: string;
  techniqueId: string;
  technique: string;
};

/** Why an alert fired: the matched clauses and the events that satisfied them. */
export type AlertEvidence = {
  ruleType: "SINGLE" | "THRESHOLD" | "SEQUENCE";
  matchedConditions: string[];
  eventIds: string[];
  eventCount: number;
  groupKey?: string;
  windowSeconds?: number;
  firstSeen?: string;
  lastSeen?: string;
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
  ruleVersion?: number;
  mitre?: MitreTechnique[];
  evidence?: AlertEvidence;
};

export type AlertHistoryEntry = {
  alertId: string;
  action: string;
  fromStatus?: AlertStatus;
  toStatus?: AlertStatus;
  actor: string;
  detail?: string;
  occurredAt: string;
};

export type AlertPage = { items: SiemAlert[]; total: number; page: number; size: number };

export type AlertSummary = {
  total: number;
  byStatus: Record<string, number>;
  openBySeverity: Record<string, number>;
  topRules: { ruleId: string; ruleName: string; alerts: number }[];
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

export type RuleCondition = {
  eventTypes?: string[];
  category?: string;
  severityMin?: string;
  messageContainsAny?: string[];
  attributeContainsAny?: Record<string, string[]>;
  attributeEquals?: Record<string, string[]>;
  destinationPorts?: number[];
  externalDestination?: boolean;
};

export type RuleType = "SINGLE" | "THRESHOLD" | "SEQUENCE";

export type DetectionRule = {
  id: string;
  version: number;
  name: string;
  description?: string;
  severity: EventSeverity;
  enabled: boolean;
  type: RuleType;
  condition: RuleCondition;
  threshold?: {
    groupBy: string[];
    windowSeconds: number;
    count?: number;
    distinctField?: string;
    sumAttribute?: string;
    minimum?: number;
    maxJitterRatio?: number;
  };
  sequence?: {
    groupBy: string[];
    windowSeconds: number;
    steps: { name: string; condition: RuleCondition; minCount?: number }[];
  };
  suppressionSeconds?: number;
  mitre: MitreTechnique[];
  falsePositives: string[];
  examples: { match: Partial<SecurityEvent>[]; noMatch: Partial<SecurityEvent>[] };
};

export type RuleChange = {
  ruleId: string;
  action: "ENABLE" | "DISABLE" | "SET_SEVERITY";
  severity?: EventSeverity;
  actor?: string;
  changedAt?: string;
  resultingVersion?: number;
};

export type RuleTestResult = {
  ruleId: string;
  ruleVersion: number;
  ruleType: RuleType;
  alerts: SiemAlert[];
  examplesPassed?: boolean;
  checks?: Record<string, boolean>;
};

export type DetectionSummary = {
  eventsEvaluated: number;
  alertsGenerated: number;
  rulesEnabled: number;
  rulesTotal?: number;
  alertsByRule?: Record<string, number>;
  detectionLatencyMeanMs?: number;
  detectionLatencyP95Ms?: number;
  recentAlerts: SiemAlert[];
};

export type IndicatorType = "IP" | "DOMAIN" | "MD5" | "SHA1" | "SHA256";

export type Indicator = {
  id: string;
  type: IndicatorType;
  value: string;
  severity: EventSeverity;
  description?: string;
  source: "ANALYST" | "SIMULATED_DEMO" | string;
  createdBy: string;
  createdAt: string;
  expiresAt?: string;
  active: boolean;
};

export type Sighting = {
  indicatorId: string;
  type: IndicatorType;
  value: string;
  eventId: string;
  field: string;
  eventTime: string;
  recordedAt: string;
};

export type AuditEntry = {
  id: number;
  occurredAt: string;
  actor: string;
  action: string;
  resourceType: string;
  resourceId: string;
  detail?: string;
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
  attributes?: Record<string, string>;
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

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:18080";

async function authenticatedHeaders(): Promise<Record<string, string>> {
  const token = await getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function sendJson<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers = {
    "Content-Type": "application/json",
    ...(await authenticatedHeaders())
  };
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal
  });
  if (!response.ok) {
    throw new ApiError(await errorMessage(response, method, path), response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/** Prefers the server's problem-detail text (e.g. "Cannot move alert from RESOLVED to ACKNOWLEDGED"). */
async function errorMessage(response: Response, method: string, path: string) {
  try {
    const body = (await response.json()) as { detail?: string; message?: string };
    if (body.detail || body.message) {
      return `${body.detail ?? body.message} (HTTP ${response.status})`;
    }
  } catch {
    // not JSON
  }
  return `${method} ${path} failed: HTTP ${response.status}`;
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

export async function apiDelete(path: string): Promise<void> {
  return sendJson<void>("DELETE", path);
}

export type ServiceHealth = "ready" | "restricted" | "offline";

const HEALTH_TIMEOUT_MS = 4_000;

/**
 * 401/403 means the service answered but the signed-in role may not see it; anything else is treated
 * as down. A timeout keeps one unreachable service (the gateway can take ~15s to give up) from
 * stalling the whole panel.
 */
export async function fetchServiceHealth(path: string): Promise<ServiceHealth> {
  try {
    const status = await sendJson<ServiceStatus>("GET", path, undefined, AbortSignal.timeout(HEALTH_TIMEOUT_MS));
    return status.status === "READY" ? "ready" : "offline";
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      return "restricted";
    }
    return "offline";
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
  "PATCH_APPLIED",
  "POWERSHELL",
  "PROCESS_CREATE",
  "FIREWALL_DENY",
  "NETWORK_FLOW",
  "OUTBOUND_CONNECTION",
  "FILE_CREATED",
  "AUDIT_LOG_CLEARED",
  "GROUP_MEMBERSHIP_ADD",
  "USER_CREATED"
];

export const eventSeverities: EventSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const incidentStatuses: IncidentStatus[] = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];