#!/usr/bin/env bash
# secrets.sh — detecção de segredos no código com Gitleaks.

# shellcheck shell=bash

run_secrets() {
  if ! is_true "$ENABLE_SECRETS"; then
    record_status "secrets" "skipped" "ENABLE_SECRETS=0" 0
    return 0
  fi

  step "Segredos"
  local started rc=0
  started="$(epoch_s)"

  component_names
  local out_dir="$RUN_DIR/raw/secrets"
  mkdir -p "$out_dir"

  for i in "${!COMPONENT_NAMES[@]}"; do
    local name="${COMPONENT_NAMES[$i]}"
    local path="${COMPONENT_PATHS[$i]}"
    local out="$out_dir/gitleaks-$name.json"

    log "Gitleaks: $name"
    local code=0
    local args=(detect --source /repo --report-format json --report-path "/out/gitleaks-$name.json" --redact --no-git --exit-code 0)

    if [[ "${GITLEAKS_HISTORY:-0}" == "1" ]]; then
      args=(detect --source /repo --report-format json --report-path "/out/gitleaks-$name.json" --redact --exit-code 0)
    fi

    docker run --rm \
      -v "$path:/repo:ro" \
      -v "$out_dir:/out" \
      zricethezav/gitleaks:latest "${args[@]}" \
      >>"$RUN_DIR/logs/gitleaks-$name.log" 2>&1 || code=$?

    if [[ "$code" -ne 0 ]] || [[ ! -f "$out" ]]; then
      warn "Gitleaks falhou em $name (rc=$code). Veja logs/gitleaks-$name.log"
      rc=1
      continue
    fi

    local n
    n="$(jq -r 'if type=="array" then length else 0 end' "$out" 2>/dev/null || echo 0)"
    ok "Gitleaks: $name → $n achado(s)"
  done

  if [[ "$rc" -eq 0 ]]; then
    record_status "secrets" "ok" "varredura de segredos concluída" "$(( $(epoch_s) - started ))"
  else
    record_status "secrets" "partial" "varredura de segredos falhou em um ou mais componentes" "$(( $(epoch_s) - started ))"
  fi
  return 0
}
