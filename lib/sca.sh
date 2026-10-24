#!/usr/bin/env bash
# sca.sh — composição de software: Syft (SBOM) + Grype + Dependency-Track.

# shellcheck shell=bash

run_sca() {
  if ! is_true "$ENABLE_SCA"; then
    record_status "sca" "skipped" "ENABLE_SCA=0" 0
    return 0
  fi

  step "SCA"
  local started rc=0
  started="$(epoch_s)"

  component_names
  for i in "${!COMPONENT_NAMES[@]}"; do
    local name="${COMPONENT_NAMES[$i]}"
    local path="${COMPONENT_PATHS[$i]}"

    generate_sbom "$name" "$path" || rc=1
    [[ -f "$RUN_DIR/raw/sca/syft-$name.cdx.json" ]] || continue

    if is_true "$ENABLE_GRYPE"; then
      run_grype "$name" || rc=1
    fi
    if is_true "$ENABLE_DTRACK"; then
      run_dtrack "$name" || rc=1
    fi
  done

  if [[ "$rc" -eq 0 ]]; then
    record_status "sca" "ok" "SBOM e análise de dependências concluídos" "$(( $(epoch_s) - started ))"
  else
    record_status "sca" "partial" "um ou mais passos de SCA falharam" "$(( $(epoch_s) - started ))"
  fi
  return 0
}

generate_sbom() {
  local name="$1" path="$2"
  local out_dir="$RUN_DIR/raw/sca"
  local out="$out_dir/syft-$name.cdx.json"

  log "Syft: $name"
  if have syft; then
    syft "dir:$path" -o "cyclonedx-json=$out" -q >>"$RUN_DIR/logs/syft-$name.log" 2>&1 || {
      warn "Syft falhou em $name"
      return 1
    }
  else
    docker run --rm \
      -v "$path:/src:ro" \
      -v "$out_dir:/out" \
      ghcr.io/anchore/syft:latest \
      "dir:/src" -o "cyclonedx-json=/out/syft-$name.cdx.json" -q \
      >>"$RUN_DIR/logs/syft-$name.log" 2>&1 || {
      warn "Syft falhou em $name"
      return 1
    }
  fi

  if [[ -s "$out" ]]; then
    local n
    n="$(jq -r '.components | length' "$out" 2>/dev/null || echo 0)"
    ok "Syft: $name → $n componente(s)"
    return 0
  fi
  return 1
}

run_grype() {
  local name="$1"
  local dir="$RUN_DIR/raw/sca"
  local out="$dir/grype-$name.json"

  log "Grype: $name"
  docker run --rm \
    -v "$dir:/work" \
    ghcr.io/anchore/grype:latest \
    "sbom:/work/syft-$name.cdx.json" -o json --file "/work/grype-$name.json" -q \
    >>"$RUN_DIR/logs/grype-$name.log" 2>&1 || {
    warn "Grype falhou em $name (o SCA do Dependency-Track continua válido)"
    return 1
  }

  local n
  n="$(jq -r '.matches | length' "$out" 2>/dev/null || echo 0)"
  ok "Grype: $name → $n correspondência(s)"
  return 0
}

ensure_dtrack_key() {
  if [[ -n "${DTRACK_API_KEY:-}" ]]; then
    return 0
  fi

  log "Dependency-Track: obtendo API key via login"
  local login_body jwt code
  local login_out="$RUN_DIR/raw/sca/.dtrack-login.txt"

  # A API de login espera form-urlencoded e devolve o JWT como texto puro.
  code="$(curl -sS -o "$login_out" -w '%{http_code}' -X POST "$DTRACK_URL/api/v1/user/login" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=$DTRACK_ADMIN_USER" \
    --data-urlencode "password=$DTRACK_ADMIN_PASSWORD" 2>/dev/null || echo 000)"

  jwt="$(tr -d '\r\n' < "$login_out" 2>/dev/null || true)"
  if jq -e . >/dev/null 2>&1 <<<"$jwt"; then
    jwt="$(jq -r '.token // empty' <<<"$jwt" 2>/dev/null || true)"
  fi

  if [[ "$code" != "200" || -z "$jwt" ]]; then
    if [[ "$jwt" == *FORCE_PASSWORD_CHANGE* ]]; then
      warn "Dependency-Track exige troca da senha inicial do admin."
      warn "conclua o primeiro acesso em http://localhost:9080 e defina DTRACK_ADMIN_PASSWORD"
      warn "ou crie uma API key e defina DTRACK_API_KEY no *.secrets.env."
    else
      warn "login no Dependency-Track falhou (HTTP $code); defina DTRACK_API_KEY no *.secrets.env"
    fi
    return 1
  fi

  local team_uuid
  team_uuid="$(curl -sS "$DTRACK_URL/api/v1/team" -H "Authorization: Bearer $jwt" 2>/dev/null \
    | jq -r 'if type=="array" then (.[0].uuid // empty) else (.uuid // empty) end' 2>/dev/null || true)"

  if [[ -z "$team_uuid" ]]; then
    warn "nenhum time encontrado no Dependency-Track"
    return 1
  fi

  local resp key
  for method in PUT POST; do
    resp="$(curl -sS -X "$method" "$DTRACK_URL/api/v1/team/$team_uuid/key" \
      -H "Authorization: Bearer $jwt" \
      -H 'Content-Type: application/json' 2>/dev/null || true)"
    key="$(jq -r '.key // empty' <<<"$resp" 2>/dev/null || true)"
    [[ -n "$key" ]] && break
  done

  if [[ -z "$key" ]]; then
    warn "não foi possível criar API key no Dependency-Track; defina DTRACK_API_KEY"
    return 1
  fi

  DTRACK_API_KEY="$key"
  ok "API key do Dependency-Track criada"
  return 0
}

wait_dtrack_bom() {
  local token="$1" timeout="${2:-300}"
  local i=0
  while (( i < timeout )); do
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "X-Api-Key: $DTRACK_API_KEY" \
      "$DTRACK_URL/api/v1/bom/token/$token" 2>/dev/null || echo 000)"
    [[ "$code" == "200" ]] && return 0
    sleep 5
    i=$((i + 5))
  done
  return 1
}

run_dtrack() {
  local name="$1"
  local sbom="$RUN_DIR/raw/sca/syft-$name.cdx.json"
  local project="${RUN_NAME}-${name}"
  local version="${PROJECT_VERSION:-1.0.0}"
  local out="$RUN_DIR/raw/sca/dtrack-findings-$name.json"

  ensure_dtrack_key || return 1

  log "Dependency-Track: enviando SBOM de $name"
  local resp token
  resp="$(curl -sS -X POST "$DTRACK_URL/api/v1/bom" \
    -H "X-Api-Key: $DTRACK_API_KEY" \
    -H 'Accept: application/json' \
    -F "projectName=$project" \
    -F "projectVersion=$version" \
    -F "autoCreate=true" \
    -F "bom=@$sbom" 2>/dev/null || true)"
  token="$(jq -r '.token // empty' <<<"$resp" 2>/dev/null || true)"

  if [[ -z "$token" ]]; then
    warn "upload do SBOM falhou ($name): $(jq -r '.message // empty' <<<"$resp" 2>/dev/null || true)"
    return 1
  fi

  if ! wait_dtrack_bom "$token" 300; then
    warn "Dependency-Track ainda processando o SBOM de $name (300s)"
    return 1
  fi

  local project_uuid
  project_uuid="$(curl -sS -H "X-Api-Key: $DTRACK_API_KEY" \
    "$DTRACK_URL/api/v1/project?name=$project&version=$version" 2>/dev/null \
    | jq -r 'if type=="array" then (.[0].uuid // empty) else (.uuid // empty) end' 2>/dev/null || true)"

  if [[ -z "$project_uuid" ]]; then
    warn "projeto não encontrado no Dependency-Track: $project/$version"
    return 1
  fi

  local raw
  raw="$(curl -sS -H "X-Api-Key: $DTRACK_API_KEY" \
    "$DTRACK_URL/api/v1/finding/project/$project_uuid" 2>/dev/null || true)"

  if ! jq -e 'type=="array" or type=="object"' >/dev/null 2>&1 <<<"$raw"; then
    raw="$(curl -sS -H "X-Api-Key: $DTRACK_API_KEY" \
      "$DTRACK_URL/api/v1/vulnerability/project/$project_uuid" 2>/dev/null || true)"
  fi

  jq 'if type=="array" then . else (.content // .findings // .vulnerabilities // []) end' \
    <<<"$raw" > "$out" 2>/dev/null || printf '[]' > "$out"

  local n
  n="$(jq -r 'length' "$out" 2>/dev/null || echo 0)"
  ok "Dependency-Track: $name → $n achado(s)"
  return 0
}
