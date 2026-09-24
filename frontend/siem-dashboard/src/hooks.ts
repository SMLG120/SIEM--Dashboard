import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  apiGet,
  apiPatch,
  apiPost,
  type AlertDetail,
  type CreateIncidentInput,
  type DetectionRule,
  type DetectionSummary,
  type Incident,
  type IngestEventInput,
  type LinkAlertInput,
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
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
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
    mutationFn: (text: string) => apiPost<Incident>(`/api/incidents/${id}/notes`, { text }),
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