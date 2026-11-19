import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  apiDelete,
  apiGet,
  apiPatch,
  apiPost,
  type AlertDetail,
  type AlertHistoryEntry,
  type AlertPage,
  type AlertStatus,
  type AlertSummary,
  type AuditEntry,
  type Indicator,
  type IndicatorType,
  type IncidentNote,
  type RuleChange,
  type RuleTestResult,
  type Sighting,
  type CreateIncidentInput,
  type DetectionRule,
  type DetectionSummary,
  type EventSeverity,
  type Incident,
  type IngestEventInput,
  type LinkAlertInput,
  type SearchHit,
  type SearchSummary,
  type SecurityEvent,
  type SiemAlert,
  type UpdateIncidentInput
} from "./api";

export function useEvents() {
  return useQuery({
    queryKey: ["events"],
    queryFn: () => apiGet<SecurityEvent[]>("/api/events"),
    refetchInterval: 10_000
  });
}

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: () => apiGet<SiemAlert[]>("/api/alerts"),
    refetchInterval: 10_000
  });
}

export function useIncidents() {
  return useQuery({
    queryKey: ["incidents"],
    queryFn: () => apiGet<Incident[]>("/api/incidents"),
    refetchInterval: 10_000
  });
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: ["incidents", id],
    queryFn: () => apiGet<Incident>(`/api/incidents/${id}`),
    enabled: id.length > 0
  });
}

export function useDetectionSummary() {
  return useQuery({
    queryKey: ["detection-summary"],
    queryFn: () => apiGet<DetectionSummary>("/api/detection/summary"),
    refetchInterval: 10_000
  });
}

export function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: () => apiGet<DetectionRule[]>("/api/rules"),
    refetchInterval: 30_000
  });
}

export function useRuleUpdate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      action,
      severity
    }: {
      id: string;
      action: "enable" | "disable" | "severity";
      severity?: EventSeverity;
    }) =>
      action === "severity"
        ? apiPost<DetectionRule>(`/api/rules/${id}/severity`, { severity })
        : apiPost<DetectionRule>(`/api/rules/${id}/${action}`),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] });
      void queryClient.invalidateQueries({ queryKey: ["detection-summary"] });
    }
  });
}

export function useIngestEvent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: IngestEventInput) => apiPost<SecurityEvent>("/api/events", input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["detection-summary"] });
    }
  });
}

export function useUpdateAlertStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      action
    }: {
      id: string;
      action: "acknowledge" | "investigate" | "resolve" | "reopen";
    }) => apiPost<SiemAlert>(`/api/alerts/${id}/${action}`),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["alert-search"] });
      void queryClient.invalidateQueries({ queryKey: ["alert-summary"] });
    }
  });
}

export function useAlertWorkflow(id: string) {
  return useQuery({
    queryKey: ["alerts", id, "workflow"],
    queryFn: () => apiGet<AlertDetail>(`/api/alerts/${id}/workflow`),
    enabled: id.length > 0
  });
}

export function useAlertAssign() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, assignedTo }: { id: string; assignedTo: string }) =>
      apiPost<AlertDetail>(`/api/alerts/${id}/assign`, { assignedTo }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    }
  });
}

export function useCreateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateIncidentInput) => apiPost<Incident>("/api/incidents", input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    }
  });
}

export function useUpdateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: UpdateIncidentInput }) =>
      apiPatch<Incident>(`/api/incidents/${id}`, input),
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents", variables.id] });
    }
  });
}

export function useAddIncidentNote(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    // The API returns the created note, not the incident.
    mutationFn: (text: string) => apiPost<IncidentNote>(`/api/incidents/${id}/notes`, { text }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents", id] });
    }
  });
}

export function useLinkAlertToIncident(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: LinkAlertInput) => apiPost<Incident>(`/api/incidents/${id}/alerts`, input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["incidents", id] });
    }
  });
}

export function useSearchSummary() {
  return useQuery({
    queryKey: ["search-summary"],
    queryFn: () => apiGet<SearchSummary>("/api/search/summary"),
    refetchInterval: 15_000
  });
}

export function useSearchEvents(query: string) {
  return useQuery({
    queryKey: ["search", "events", query],
    queryFn: () => apiGet<SearchHit[]>(`/api/search/events?q=${encodeURIComponent(query)}`),
    enabled: query.trim().length > 0
  });
}

export function useSearchAlerts(query: string) {
  return useQuery({
    queryKey: ["search", "alerts", query],
    queryFn: () => apiGet<SearchHit[]>(`/api/search/alerts?q=${encodeURIComponent(query)}`),
    enabled: query.trim().length > 0
  });
}

export type AlertFilters = {
  status: AlertStatus[];
  severity: EventSeverity[];
  ruleId?: string;
  sourceIp?: string;
  assignedTo?: string;
  sort: "created" | "severity";
  page: number;
  size: number;
};

export function alertSearchPath(f: AlertFilters) {
  const params = new URLSearchParams();
  f.status.forEach((s) => params.append("status", s));
  f.severity.forEach((s) => params.append("severity", s));
  if (f.ruleId) params.set("ruleId", f.ruleId);
  if (f.sourceIp) params.set("sourceIp", f.sourceIp);
  if (f.assignedTo) params.set("assignedTo", f.assignedTo);
  params.set("sort", f.sort);
  params.set("page", String(f.page));
  params.set("size", String(f.size));
  return `/api/alerts/search?${params.toString()}`;
}

export function useAlertSearch(filters: AlertFilters) {
  return useQuery({
    queryKey: ["alert-search", filters],
    queryFn: () => apiGet<AlertPage>(alertSearchPath(filters)),
    refetchInterval: 10_000,
    placeholderData: (previous) => previous
  });
}

export function useAlertSummary() {
  return useQuery({
    queryKey: ["alert-summary"],
    queryFn: () => apiGet<AlertSummary>("/api/alerts/summary"),
    refetchInterval: 10_000
  });
}

export function useAlertHistory(id: string) {
  return useQuery({
    queryKey: ["alerts", id, "history"],
    queryFn: () => apiGet<AlertHistoryEntry[]>(`/api/alerts/${id}/history`),
    enabled: id.length > 0
  });
}

export function useEvent(id: string | undefined) {
  return useQuery({
    queryKey: ["events", id],
    queryFn: () => apiGet<SecurityEvent>(`/api/events/${id}`),
    enabled: Boolean(id),
    staleTime: Infinity // events are immutable
  });
}

export function useAddAlertNote(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (text: string) => apiPost(`/api/alerts/${id}/notes`, { text }),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts", id] });
    }
  });
}

export function useRuleHistory(id: string | undefined) {
  return useQuery({
    queryKey: ["rules", id, "history"],
    queryFn: () => apiGet<RuleChange[]>(`/api/rules/${id}/history`),
    enabled: Boolean(id)
  });
}

export function useRuleTest() {
  return useMutation({
    mutationFn: (body: { ruleId: string; events?: Partial<SecurityEvent>[] }) =>
      apiPost<RuleTestResult>("/api/rules/test", body)
  });
}

export function useIndicators() {
  return useQuery({
    queryKey: ["indicators"],
    queryFn: () => apiGet<Indicator[]>("/api/threat-intel/indicators"),
    refetchInterval: 30_000
  });
}

export function useSightings() {
  return useQuery({
    queryKey: ["sightings"],
    queryFn: () => apiGet<Sighting[]>("/api/threat-intel/sightings?limit=100"),
    refetchInterval: 15_000
  });
}

export function useCreateIndicator() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { type: IndicatorType; value: string; severity: EventSeverity; description?: string }) =>
      apiPost<Indicator>("/api/threat-intel/indicators", input),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["indicators"] })
  });
}

export function useDeactivateIndicator() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiDelete(`/api/threat-intel/indicators/${id}`),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["indicators"] })
  });
}

export function useAuditLog(enabled: boolean) {
  return useQuery({
    queryKey: ["audit"],
    queryFn: () => apiGet<AuditEntry[]>("/api/audit/events?limit=50"),
    enabled,
    refetchInterval: 30_000
  });
}
