{{- define "gw.fullname" -}}
{{- printf "%s-xmsg-mcp-gateway" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gw.selectorLabels" -}}
app.kubernetes.io/name: xmsg-mcp-gateway
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "gw.labels" -}}
{{ include "gw.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{/* An image reference: the digest when set, else the tag. */}}
{{- define "gw.image" -}}
{{- if .digest -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else -}}
{{- printf "%s:%s" .repository (required (printf "%s needs a tag or a digest" .repository) .tag) -}}
{{- end -}}
{{- end -}}

{{/* Every container's securityContext. */}}
{{- define "gw.hardened" -}}
runAsUser: {{ int .Values.uid }}
runAsGroup: {{ int .Values.uid }}
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
{{- end -}}

{{/* In-pod paths. The chart owns them so every container agrees. */}}
{{- define "gw.dataDir" -}}/var/lib/xmsg-mcp-gateway{{- end -}}
{{- define "gw.grantStore" -}}{{ include "gw.dataDir" . }}/state/grants.db{{- end -}}
{{- define "gw.leafDb" -}}{{ include "gw.dataDir" . }}/xmsg/xmsg.db{{- end -}}
{{- define "gw.keysDir" -}}/run/xmsg-mcp-gateway/keys{{- end -}}
{{- define "gw.secretsDir" -}}/run/secrets/xmsg-mcp-gateway{{- end -}}
{{- define "gw.configDir" -}}/etc/xmsg-mcp-gateway{{- end -}}
{{- define "gw.runtimeDir" -}}/run/user{{- end -}}

{{/* serving.json: the owner's values with the pod-owned fields set over them. */}}
{{- define "gw.serving" -}}
{{- $v := .Values -}}
{{- $s := deepCopy $v.serving -}}
{{- $port := int $v.gateway.port -}}
{{- $lim := $v.xmsg.limits -}}
{{- $userMsg := $s.messaging | default dict -}}
{{- $userMan := $userMsg.manifest | default dict -}}
{{- $owned := dict
  "bind" (printf "%s:%d" (ternary "0.0.0.0" "127.0.0.1" $v.gateway.podNetwork) $port)
  "grant_store" (include "gw.grantStore" .)
  "messaging" (dict
    "xmsg" (dict
      "service" (required "xmsg.principal is required" $v.xmsg.principal)
      "daemon_uid" (int $v.uid)
      "register_socket" (printf "%s/xmsg/register.sock" (include "gw.runtimeDir" .))
      "agent_socket" (printf "%s/xmsg/agent.sock" (include "gw.runtimeDir" .)))
    "manifest" (dict
      "reply_ttl_secs" (int $lim.replyTtl)
      "idempotency_ttl_secs" (int $lim.idempotencyTtl)
      "svc_queue_cap" (int $lim.svcQueueCap)
      "dedup_lifetime_secs" (int ($userMan.dedup_lifetime_secs | default (div (int $lim.idempotencyTtl) 2)))
      "max_framed_bytes" (int ($userMan.max_framed_bytes | default $lim.maxBody))))
-}}
{{- if $v.gateway.podNetwork -}}
{{- $_ := set $owned "allow_non_loopback_bind" true -}}
{{- else -}}
{{- $_ := unset $s "allow_non_loopback_bind" -}}
{{- end -}}
{{- mustMergeOverwrite $s $owned | toJson -}}
{{- end -}}

{{/* The budget rules the gateway enforces at startup, refused at render instead.
     Each rule runs when its own field is set; a missing verifier timeout counts 0. */}}
{{- define "gw.checkBudgets" -}}
{{- $s := .Values.serving -}}
{{- $vt := 0 -}}
{{- with $s.verifier }}{{ $vt = int (.timeout_ms | default 0) }}{{ end -}}
{{- range ($s.verifier_profiles | default list) }}{{ $vt = max $vt (int (.timeout_ms | default 0)) }}{{ end -}}
{{- $rt := int ($s.request_timeout_ms | default 0) -}}
{{- $msg := $s.messaging | default dict -}}
{{- with ($s.events | default dict).dispatch_timeout_ms -}}
{{- if or (lt (int .) (add $vt 11000)) (gt (int .) 60000) -}}
{{- fail "serving.events.dispatch_timeout_ms must be >= verifier timeout_ms + 11000 and <= 60000" -}}
{{- end -}}
{{- end -}}
{{- if $rt -}}
{{- if or (lt $rt (add (mul 2 $vt) 41000)) (gt $rt 60000) -}}
{{- fail "serving.request_timeout_ms must be >= 2 * verifier timeout_ms + 41000 and <= 60000" -}}
{{- end -}}
{{- with $msg.submission_timeout_ms -}}
{{- if or (gt (int .) 25000) (lt $rt (add $vt 30000 (int .))) -}}
{{- fail "serving.request_timeout_ms must cover verifier timeout_ms + the 30 s store wait + messaging.submission_timeout_ms (<= 25000)" -}}
{{- end -}}
{{- end -}}
{{- with ($msg.xmsg | default dict).operation_timeout_ms -}}
{{- if or (le (int .) 11000) (lt $rt (add $vt 30000 (int .))) -}}
{{- fail "messaging.xmsg.operation_timeout_ms must be > 11000, and serving.request_timeout_ms must cover verifier timeout_ms + the 30 s store wait + it" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.gateway.podNetwork (not (has "127.0.0.1" ($s.allowed_hosts | default list))) -}}
{{- fail "gateway.podNetwork renders probes that send Host: 127.0.0.1; add it to serving.allowed_hosts" -}}
{{- end -}}
{{- if and .Values.tunnel.enabled (not (has "127.0.0.1" ($s.allowed_hosts | default list))) -}}
{{- fail "tunnel-client reaches the gateway at 127.0.0.1; add it to serving.allowed_hosts" -}}
{{- end -}}
{{- if and .Values.httpRoute.enabled (not .Values.gateway.podNetwork) -}}
{{- fail "httpRoute needs gateway.podNetwork: the proxy reaches the gateway on the pod network" -}}
{{- end -}}
{{- end -}}

{{/* One gateway-CLI store step: the image's own entrypoint, no command override. */}}
{{- define "gw.storeStep" -}}
- name: {{ .name }}
  image: {{ include "gw.image" .ctx.Values.image | quote }}
  imagePullPolicy: {{ .ctx.Values.image.pullPolicy }}
  args: {{ concat (list "--state" .store) .args | toJson }}
  securityContext:
    {{- include "gw.hardened" .ctx | nindent 4 }}
  volumeMounts:
    - {name: data, mountPath: {{ include "gw.dataDir" .ctx }}}
    - {name: keys, mountPath: {{ dir (include "gw.keysDir" .ctx) }}, readOnly: true}
    - {name: config, mountPath: {{ include "gw.configDir" .ctx }}, readOnly: true}
{{- end -}}

{{/* The gateway's migrations in its order (docs/serving.md), each a no-op when done. */}}
{{- define "gw.migrations" -}}
{{- $ctx := .ctx -}}
{{- $key := list -}}
{{- with $ctx.Values.store.eventsKey }}{{ $key = list "--key-file" (printf "%s/%s" (include "gw.keysDir" $ctx) .) }}{{ end -}}
{{- $steps := list
  (list "migrate-custody")
  (list "migrate-outbound")
  (list "migrate-retirement")
  (list "migrate-custody-summaries")
  (concat (list "migrate-events") $key)
  (list "migrate-profiles")
  (list "migrate-attachments") -}}
{{- if $ctx.Values.store.authorizationServer }}{{ $steps = append $steps (list "migrate-authorization-server") }}{{ end -}}
{{- range $steps }}
{{ include "gw.storeStep" (dict "ctx" $ctx "name" (printf "%s-%s" $.prefix (first .)) "store" $.store "args" (concat (list (first .) "--if-needed") (rest .))) }}
{{- end -}}
{{- end -}}
