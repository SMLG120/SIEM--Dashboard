{{- define "siem.labels" -}}
app.kubernetes.io/part-of: enterprise-siem
app.kubernetes.io/managed-by: Helm
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "siem.fullname" -}}
{{- default "siem" .Values.global.namePrefix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Restricted pod security for the SIEM's own images (non-root numeric UIDs baked in). */}}
{{- define "siem.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ . }}
runAsGroup: {{ . }}
fsGroup: {{ . }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "siem.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
{{- end -}}
