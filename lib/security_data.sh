# shellcheck shell=bash
SECURITY_CACHE="$DEVSEC_ROOT/.cache/security"

security_image() {
  local name="$1" image
  image="$(jq -r --arg name "$name" '.images[$name].id // empty' "$SECURITY_CACHE/manifest.json" 2>/dev/null || true)"
  [[ -n "$image" ]] || { warn "Imagem $name sem registro; execute ./bin/devsec update"; return 1; }
  printf '%s' "$image"
}

prepare_security_data() {
  if ! is_true "$ENABLE_SAST" && ! is_true "$ENABLE_SCA" && ! is_true "$ENABLE_SECRETS"; then return 0; fi
  local rc=0
  if is_true "${AUTO_UPDATE_SECURITY_DATA:-1}"; then
    python3 "$DEVSEC_ROOT/lib/security_data.py" update >"$RUN_DIR/logs/security-data.log" 2>&1 || rc=1
  else
    python3 "$DEVSEC_ROOT/lib/security_data.py" status >"$RUN_DIR/logs/security-data.log" 2>&1 || rc=1
  fi
  if [[ "$rc" -ne 0 ]]; then
    SECURITY_DATA_READY=0
    record_status "security-data" "failed" "bases ausentes, desatualizadas ou atualização falhou; veja security-data.log" 0
    return 0
  fi
  SECURITY_DATA_READY=1
  cp "$SECURITY_CACHE/manifest.json" "$RUN_DIR/security-data.json"
  record_status "security-data" "ok" "bases locais verificadas; manifesto security-data.json" 0
}
