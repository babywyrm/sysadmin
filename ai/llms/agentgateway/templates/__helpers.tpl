{{/*
  _helpers.tpl
  Shared template helpers used across all chart templates.
  These produce consistent names, labels, and selectors.
*/}}

{{/*
  agentgateway.name
  Returns the chart name, truncated to 63 characters (K8s label limit).
  Can be overridden with .Values.nameOverride.
*/}}
{{- define "agentgateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
  agentgateway.fullname
  Returns a fully qualified release+chart name, truncated to 63 chars.
  Can be overridden entirely with .Values.fullnameOverride.
*/}}
{{- define "agentgateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
  agentgateway.chart
  Returns the chart name+version string used in the helm.sh/chart label.
*/}}
{{- define "agentgateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
  agentgateway.labels
  Full set of recommended Kubernetes labels applied to all resources.
  Includes both selector labels and additional metadata labels.
*/}}
{{- define "agentgateway.labels" -}}
helm.sh/chart: {{ include "agentgateway.chart" . }}
{{ include "agentgateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
  agentgateway.selectorLabels
  Minimal labels used as pod selectors in Deployments and Services.
  Must remain stable across upgrades — changing these breaks selectors.
*/}}
{{- define "agentgateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentgateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
  agentgateway.serviceAccountName
  Name of the ServiceAccount created by rbac.yaml.
*/}}
{{- define "agentgateway.serviceAccountName" -}}
{{- printf "%s-sa" (include "agentgateway.fullname" .) }}
{{- end }}
