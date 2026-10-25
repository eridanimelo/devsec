#!/usr/bin/env bash
# dast.sh — análise dinâmica com OWASP ZAP (baseline, autenticado e ativo).

# shellcheck shell=bash

ZAP_AUTH_PROP_REL=""
ZAP_CONTEXT_REL=""

run_dast() {
  if ! is_true "$ENABLE_DAST"; then
    record_status "dast" "skipped" "ENABLE_DAST=0" 0
    return 0
  fi

  if [[ "${DAST_TARGET_READY:-1}" != "1" ]]; then
    record_status "dast" "failed" "alvo inacessível após inicialização da aplicação" 0
    return 0
  fi

  step "DAST"
  local started rc=0 auth_rc=0
  started="$(epoch_s)"

  ZAP_AUTH_PROP_REL=""
  ZAP_CONTEXT_REL=""
  build_zap_auth || auth_rc=$?

  if [[ "$auth_rc" -ne 0 ]]; then
    if is_true "${AUTH_REQUIRED:-0}"; then
      warn "autenticação de teste falhou e AUTH_REQUIRED=1: DAST será pulado"
      record_status "dast" "failed" "autenticação de teste falhou" "$(( $(epoch_s) - started ))"
      cleanup_dast_auth
      return 0
    fi
    warn "autenticação de teste falhou: DAST seguirá sem autenticação"
    rc=1
    cleanup_dast_auth
  fi

  if [[ -n "${APP_URL:-}" ]]; then
    zap_baseline || rc=1
    if is_true "$ZAP_ACTIVE"; then
      zap_full || rc=1
    fi
  else
    warn "APP_URL não informado: baseline ignorado"
  fi

  if [[ -z "${APP_URL:-}" && -z "${OPENAPI_SPEC:-}" ]]; then
    warn "API_URL sem OPENAPI_SPEC: nenhuma rota de API foi analisada"
    rc=1
  fi

  if [[ -n "${OPENAPI_SPEC:-}" && -n "${API_URL:-}" ]]; then
    zap_api || rc=1
  elif [[ -n "${OPENAPI_SPEC:-}" ]]; then
    warn "OPENAPI_SPEC informado sem API_URL: scan de API ignorado"
    rc=1
  fi

  cleanup_dast_auth
  if [[ "$rc" -eq 0 ]]; then
    record_status "dast" "ok" "DAST concluído" "$(( $(epoch_s) - started ))"
  else
    record_status "dast" "partial" "DAST concluído com avisos" "$(( $(epoch_s) - started ))"
  fi
  return 0
}

zap_prop_add() {
  local index="$1" matchstr="$2" replacement="$3"
  local prop="$RUN_DIR/raw/dast/auth.prop"
  {
    printf 'replacer.full_list(%s).description=devsec-auth\n' "$index"
    printf 'replacer.full_list(%s).enabled=true\n' "$index"
    printf 'replacer.full_list(%s).matchtype=REQ_HEADER\n' "$index"
    printf 'replacer.full_list(%s).matchstr=%s\n' "$index" "$matchstr"
    printf 'replacer.full_list(%s).replacement=%s\n' "$index" "$replacement"
  } >> "$prop"
}

build_zap_auth() {
  local mode="${AUTH_MODE:-none}"

  case "$mode" in
    none)
      log "DAST: sem autenticação"
      return 0
      ;;
    header)
      [[ -n "${AUTH_HEADER:-}" ]] || { warn "AUTH_MODE=header exige AUTH_HEADER"; return 1; }
      local name="${AUTH_HEADER%%:*}"
      local value="${AUTH_HEADER#*:}"
      value="${value# }"
      : > "$RUN_DIR/raw/dast/auth.prop"
      zap_prop_add 0 "$name" "$value"
      ZAP_AUTH_PROP_REL="auth.prop"
      ok "DAST: header estático configurado ($name)"
      return 0
      ;;
    login)
      dast_login
      return $?
      ;;
    form)
      dast_form_context
      return $?
      ;;
    playwright)
      dast_playwright
      return $?
      ;;
    *)
      warn "AUTH_MODE desconhecido: $mode"
      return 1
      ;;
  esac
}

dast_login() {
  [[ -n "${AUTH_LOGIN_URL:-}" ]] || { warn "AUTH_MODE=login exige AUTH_LOGIN_URL"; return 1; }

  local body_template="${AUTH_LOGIN_BODY:-}"
  if [[ -z "$body_template" ]]; then
    body_template='{"email":"__USERNAME__","password":"__PASSWORD__"}'
  fi
  local body
  body="$(jq -cn \
    --arg tpl "$body_template" \
    --arg u "$AUTH_USERNAME" \
    --arg p "$AUTH_PASSWORD" \
    '$tpl | fromjson | walk(if type == "string" then (gsub("__USERNAME__"; $u) | gsub("__PASSWORD__"; $p)) else . end)')" \
    || { warn "AUTH_LOGIN_BODY não é um JSON válido"; return 1; }

  log "DAST: autenticando em $AUTH_LOGIN_URL"
  local headers="$RUN_DIR/raw/dast/login-headers.txt"
  local jar="$RUN_DIR/raw/dast/cookies.txt"
  local csrf_json="$RUN_DIR/raw/dast/csrf.json"
  local csrf_header="" csrf_value=""
  : > "$jar"

  # Alguns backends (Spring Security) exigem CSRF até no login.
  if [[ -n "${AUTH_CSRF_URL:-}" ]]; then
    curl -sS -c "$jar" -b "$jar" "$AUTH_CSRF_URL" -o "$csrf_json" 2>/dev/null || true
    csrf_value="$(jq -r '.token // empty' "$csrf_json" 2>/dev/null || true)"
    csrf_header="$(jq -r '.headerName // "X-XSRF-TOKEN"' "$csrf_json" 2>/dev/null || true)"
    [[ -n "$csrf_value" ]] || warn "CSRF não obtido em $AUTH_CSRF_URL"
  fi

  local curl_args=(-sS -c "$jar" -b "$jar"
    -o "$RUN_DIR/raw/dast/login-response.json" -D "$headers"
    -w '%{http_code}' -X POST
    -H 'Content-Type: application/json'
    --data "$body")
  [[ -n "$csrf_value" ]] && curl_args+=(-H "${csrf_header}: ${csrf_value}")

  local resp code
  code="$(curl "${curl_args[@]}" "$AUTH_LOGIN_URL" 2>/dev/null || echo 000)"
  resp="$(cat "$RUN_DIR/raw/dast/login-response.json" 2>/dev/null || true)"

  if [[ "$code" -lt 200 || "$code" -ge 300 ]]; then
    warn "login retornou HTTP $code"
    return 1
  fi

  : > "$RUN_DIR/raw/dast/auth.prop"
  if is_true "${AUTH_USE_COOKIE:-0}"; then
    # Repassa todos os cookies da sessão (IDENTITY_SESSION + XSRF-TOKEN).
    # curl grava cookies HttpOnly com o prefixo "#HttpOnly_" no domínio.
    local cookie_pairs
    cookie_pairs="$(awk 'NF >= 7 && ($0 !~ /^#/ || $1 ~ /^#HttpOnly_/) {printf "%s=%s; ", $6, $7}' "$jar" | sed 's/; $//')"
    [[ -n "$cookie_pairs" ]] || { warn "nenhum cookie de sessão obtido no login"; return 1; }
    zap_prop_add 0 "Cookie" "$cookie_pairs"
    # Reenvia o header CSRF nas requisições que alteram estado (active scan).
    if [[ -n "$csrf_value" ]]; then
      zap_prop_add 1 "$csrf_header" "$csrf_value"
    fi
    ok "DAST: autenticado por cookie ($(awk 'NF >= 7 && ($0 !~ /^#/ || $1 ~ /^#HttpOnly_/) {print $6}' "$jar" | paste -sd, -))"
  else
    local path="${AUTH_TOKEN_JSON_PATH:-.accessToken}"
    local token
    token="$(jq -r "$path // empty" <<<"$resp" 2>/dev/null || true)"
    [[ -n "$token" ]] || { warn "token não encontrado no JSON de login (path: $path)"; return 1; }
    local header="${AUTH_TOKEN_HEADER:-Authorization}"
    local prefix="${AUTH_TOKEN_PREFIX:-Bearer }"
    zap_prop_add 0 "$header" "${prefix}${token}"
    ok "DAST: autenticado por token ($header)"
  fi

  ZAP_AUTH_PROP_REL="auth.prop"
  if [[ -n "${AUTH_VERIFY_URL:-}" ]]; then
    local anonymous_code authenticated_code
    anonymous_code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$AUTH_VERIFY_URL" 2>/dev/null || true)"
    if [[ "$anonymous_code" != "401" && "$anonymous_code" != "403" ]]; then
      warn "AUTH_VERIFY_URL não comprovou proteção sem sessão (esperado 401/403)"
      return 1
    fi
    local verify_args=(-sS --max-time 10 -o /dev/null -w '%{http_code}')
    if is_true "${AUTH_USE_COOKIE:-0}"; then
      verify_args+=(-b "$jar")
    else
      verify_args+=(-H "$header: ${prefix}${token}")
    fi
    authenticated_code="$(curl "${verify_args[@]}" "$AUTH_VERIFY_URL" 2>/dev/null || true)"
    [[ "$authenticated_code" =~ ^2[0-9][0-9]$ ]] || {
      warn "sessão de teste não validada na rota protegida"
      return 1
    }
    run_meta_set "auth_verified" "true"
    ok "sessão de teste confirmada na rota protegida"
  fi
  return 0
}

dast_form_context() {
  [[ -n "${AUTH_LOGIN_URL:-}" ]] || { warn "AUTH_MODE=form exige AUTH_LOGIN_URL"; return 1; }

  local ctx="$RUN_DIR/raw/dast/context.context"
  local user_field="${AUTH_USER_FIELD:-username}"
  local pass_field="${AUTH_PASS_FIELD:-password}"
  local extra="${AUTH_EXTRA_FIELDS:-}"
  local login_body="${user_field}={%username%}&${pass_field}={%password%}"
  [[ -n "$extra" ]] && login_body="${extra}&${login_body}"

  cat > "$ctx" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<configuration>
  <context>
    <name>devsec</name>
    <desc>Contexto gerado pelo devsec</desc>
    <inscope>true</inscope>
    <incregexes>${APP_URL:-.*}/.*</incregexes>
    <authentication>
      <type>1</type>
      <form>
        <loginurl>${AUTH_LOGIN_URL}</loginurl>
        <loginbody>${login_body}</loginbody>
        <loginpageurl>${AUTH_LOGIN_PAGE_URL:-${APP_URL:-}}</loginpageurl>
      </form>
    </authentication>
    <session>
      <type>1</type>
    </session>
    <users>
      <user>
        <name>devsec</name>
        <enabled>true</enabled>
        <username>${AUTH_USERNAME}</username>
        <password>${AUTH_PASSWORD}</password>
      </user>
    </users>
  </context>
</configuration>
EOF
  ZAP_CONTEXT_REL="context.context"
  ok "DAST: contexto de autenticação form-based gerado"
  return 0
}

dast_playwright() {
  local script="$AUTH_PLAYWRIGHT_SCRIPT"

  if [[ -z "$script" || ! -f "$script" ]]; then
    warn "AUTH_MODE=playwright exige AUTH_PLAYWRIGHT_SCRIPT existente"
    return 1
  fi
  if ! have node; then
    warn "node não encontrado para rodar o script de login"
    return 1
  fi

  log "DAST: executando login via Playwright"
  local out="$RUN_DIR/raw/dast/playwright-headers.json"

  AUTH_USERNAME="$AUTH_USERNAME" AUTH_PASSWORD="$AUTH_PASSWORD" APP_URL="${APP_URL:-}" OUT="$out" \
    node "$script" >>"$RUN_DIR/logs/playwright-auth.log" 2>&1 || {
    warn "script de login Playwright falhou. Veja logs/playwright-auth.log"
    return 1
  }

  [[ -s "$out" ]] || { warn "script Playwright não gerou $out"; return 1; }

  : > "$RUN_DIR/raw/dast/auth.prop"
  local i=0
  while IFS=$'\t' read -r name value; do
    [[ -z "$name" ]] && continue
    zap_prop_add "$i" "$name" "$value"
    i=$((i + 1))
  done < <(jq -r '.headers // {} | to_entries[] | [.key, .value] | @tsv' "$out")

  [[ "$i" -gt 0 ]] || { warn "nenhum header retornado pelo script Playwright"; return 1; }
  ZAP_AUTH_PROP_REL="auth.prop"
  ok "DAST: autenticado via Playwright ($i header(s))"
  return 0
}

zap_docker_args() {
  ZAP_ARGS=(docker run --rm --add-host=host.docker.internal:host-gateway -v "$RUN_DIR/raw/dast:/zap/wrk:rw")
}

# O ZAP roda em container: localhost lá dentro é o próprio container.
zap_target_url() {
  local url="$1"
  printf '%s' "${url//localhost/host.docker.internal}" | sed 's/127\.0\.0\.1/host.docker.internal/g'
}

zap_common_flags() {
  local name="$1"
  ZAP_FLAGS=(-r "$name.html" -J "$name.json" -w "$name.md" -I)
  if [[ -n "$ZAP_CONTEXT_REL" ]]; then
    ZAP_FLAGS+=(-n "/zap/wrk/$ZAP_CONTEXT_REL")
  fi
  if [[ -n "$ZAP_AUTH_PROP_REL" ]]; then
    ZAP_FLAGS+=(-z "-configfile /zap/wrk/$ZAP_AUTH_PROP_REL")
  fi
  if [[ "${ZAP_TIMEOUT:-0}" -gt 0 ]]; then
    ZAP_FLAGS+=(-T "$ZAP_TIMEOUT")
  fi
}

zap_baseline() {
  local target
  target="$(zap_target_url "$APP_URL")"
  log "ZAP baseline: $APP_URL"
  zap_docker_args
  zap_common_flags "baseline"

  local code=0
  "${ZAP_ARGS[@]}" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
    -t "$target" "${ZAP_FLAGS[@]}" \
    >>"$RUN_DIR/logs/zap-baseline.log" 2>&1 || code=$?

  if [[ -s "$RUN_DIR/raw/dast/baseline.json" ]]; then
    local n
    n="$(jq -r '[.site[]?.alerts[]?] | length' "$RUN_DIR/raw/dast/baseline.json" 2>/dev/null || echo 0)"
    ok "ZAP baseline → $n alerta(s)"
    return 0
  fi

  warn "ZAP baseline falhou (rc=$code). Veja logs/zap-baseline.log"
  return 1
}

zap_full() {
  local target
  target="$(zap_target_url "$APP_URL")"
  log "ZAP full scan (ATIVO): $APP_URL"
  zap_docker_args
  zap_common_flags "full"

  local code=0
  "${ZAP_ARGS[@]}" ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t "$target" "${ZAP_FLAGS[@]}" \
    >>"$RUN_DIR/logs/zap-full.log" 2>&1 || code=$?

  if [[ -s "$RUN_DIR/raw/dast/full.json" ]]; then
    local n
    n="$(jq -r '[.site[]?.alerts[]?] | length' "$RUN_DIR/raw/dast/full.json" 2>/dev/null || echo 0)"
    ok "ZAP full → $n alerta(s)"
    return 0
  fi

  warn "ZAP full falhou (rc=$code). Veja logs/zap-full.log"
  return 1
}

zap_api() {
  local target
  target="$(zap_target_url "$API_URL")"
  log "ZAP API scan: $API_URL"
  local spec_dir spec_file
  spec_dir="$(cd "$(dirname "$OPENAPI_SPEC")" && pwd)"
  spec_file="$(basename "$OPENAPI_SPEC")"

  zap_common_flags "api"
  is_true "$ZAP_ACTIVE" || ZAP_FLAGS+=(-S)
  local code=0
  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$RUN_DIR/raw/dast:/zap/wrk:rw" \
    -v "$spec_dir:/spec:ro" \
    ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
    -t "/spec/$spec_file" -f openapi "${ZAP_FLAGS[@]}" \
    >>"$RUN_DIR/logs/zap-api.log" 2>&1 || code=$?

  if [[ -s "$RUN_DIR/raw/dast/api.json" ]]; then
    local n
    n="$(jq -r '[.site[]?.alerts[]?] | length' "$RUN_DIR/raw/dast/api.json" 2>/dev/null || echo 0)"
    ok "ZAP API → $n alerta(s)"
    return 0
  fi

  warn "ZAP API falhou (rc=$code). Veja logs/zap-api.log"
  return 1
}


cleanup_dast_auth() {
  [[ -n "${RUN_DIR:-}" ]] || return 0
  local filename
  for filename in auth.prop context.context cookies.txt csrf.json login-headers.txt login-response.json playwright-headers.json; do
    rm -f "$RUN_DIR/raw/dast/$filename"
  done
  ZAP_AUTH_PROP_REL=""
  ZAP_CONTEXT_REL=""
}
