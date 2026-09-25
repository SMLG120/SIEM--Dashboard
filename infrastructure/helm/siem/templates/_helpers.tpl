{{- define "siem.labels" -}}
app.kubernetes.io/part-of: enterprise-siem
app.kubernetes.io/managed-by: Helm
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "siem.fullname" -}}
{{- default "siem" .Values.global.namePrefix | trunc 63 | trimSuffix "-" -}}
{{- end -}}