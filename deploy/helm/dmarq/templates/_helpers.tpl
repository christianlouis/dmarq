{{- define "dmarq.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dmarq.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "dmarq.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "dmarq.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "dmarq.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "dmarq.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "dmarq.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dmarq.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: app
{{- end }}

{{- define "dmarq.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dmarq.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dmarq.requirements" -}}
{{- if not .Values.existingSecret }}
{{- fail "existingSecret is required and must contain DATABASE_URL, SECRET_KEY, and ADMIN_API_KEY" }}
{{- end }}
{{- if and (eq .Values.config.environment "production") (eq .Values.config.authMode "disabled") (not .Values.config.allowAuthDisabledInProduction) }}
{{- fail "production installs must configure authentication or explicitly allow auth-disabled mode" }}
{{- end }}
{{- if and .Values.bootstrap.enabled (not .Values.bootstrap.ownerEmail) }}
{{- fail "bootstrap.ownerEmail is required when bootstrap.enabled=true" }}
{{- end }}
{{- end }}
