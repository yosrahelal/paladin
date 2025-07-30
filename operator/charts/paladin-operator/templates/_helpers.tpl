 {{- define "checksums" -}}
operatorConfig: {{ include (printf "%s/operator/configmap.yaml" $.Template.BasePath) . | replace .Chart.AppVersion "" | sha256sum }}
{{- end -}}

{{- define "paladin-operator.paladinNodeCount" -}}
{{- $paladinCount := .Values.nodeCount | int }}
{{- if .Values.paladinNodeCount }}
{{-   $paladinCount = .Values.paladinNodeCount | int }}
{{- end }}
{{- $paladinCount }}
{{- end -}}

{{- define "paladin-operator.besuNodeCount" -}}
{{- $besuCount := .Values.nodeCount | int }}
{{- if .Values.paladinNodeCount }}
{{-   $besuCount = 1 }}
{{- end }}
{{- $besuCount }}
{{- end -}}

