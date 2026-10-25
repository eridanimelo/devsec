#!/usr/bin/env bash
# scan.sh — comandos scan, report, list e clean do CLI.

# shellcheck shell=bash

cmd_analyze() {
  local args=("$@") profile="" arg
  for arg in "$@"; do
    case "$arg" in --profile|-p) profile=explicit ;; esac
  done
  if [[ -z "$profile" ]]; then
    [[ -f "$DEVSEC_ROOT/config/default-profile" ]] || die "configure config/default-profile ou informe --profile"
    IFS= read -r profile < "$DEVSEC_ROOT/config/default-profile" || true
    [[ -n "$profile" ]] || die "config/default-profile está vazio"
    args=(--profile "$(resolve_path "$profile")" "${args[@]}")
  fi
  cmd_scan "${args[@]}"
}

cmd_scan() {
  local profile="" only="" skip="" baseline="" open=0
  local active=0 authorized=0 no_stack=0 run_id=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile|-p) profile="${2:?--profile exige um valor}"; shift 2 ;;
      --only) only="${2:?--only exige um valor}"; shift 2 ;;
      --skip) skip="${2:?--skip exige um valor}"; shift 2 ;;
      --baseline) baseline="${2:?--baseline exige um valor}"; shift 2 ;;
      --run-id) run_id="${2:?--run-id exige um valor}"; shift 2 ;;
      --active) active=1; shift ;;
      --i-have-authorization) authorized=1; shift ;;
      --no-stack) no_stack=1; shift ;;
      --open) open=1; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "opção desconhecida: $1" ;;
    esac
  done

  [[ -n "$profile" ]] || die "informe --profile <arquivo.env>"

  load_profile "$profile"

  # Overrides de linha de comando vencem o perfil.
  [[ "$active" == "1" ]] && ZAP_ACTIVE=1
  [[ "$authorized" == "1" ]] && I_HAVE_AUTHORIZATION=1
  [[ "$no_stack" == "1" ]] && STACK_UP=0
  [[ -n "$run_id" ]] && RUN_ID="$run_id"

  if [[ -n "$only" ]]; then
    local sel=",$only,"
    [[ "$sel" == *",sast,"* ]] || ENABLE_SAST=0
    [[ "$sel" == *",sca,"* ]] || ENABLE_SCA=0
    [[ "$sel" == *",secrets,"* ]] || ENABLE_SECRETS=0
    [[ "$sel" == *",dast,"* ]] || ENABLE_DAST=0
  fi
  if [[ -n "$skip" ]]; then
    local sel=",$skip,"
    [[ "$sel" == *",sast,"* ]] && ENABLE_SAST=0
    [[ "$sel" == *",sca,"* ]] && ENABLE_SCA=0
    [[ "$sel" == *",secrets,"* ]] && ENABLE_SECRETS=0
    [[ "$sel" == *",dast,"* ]] && ENABLE_DAST=0
  fi

  export ZAP_ACTIVE I_HAVE_AUTHORIZATION STACK_UP
  export ENABLE_SAST ENABLE_SCA ENABLE_SECRETS ENABLE_DAST

  init_run

  printf '\n%sdevsec%s  %s\n' "$C_BOLD" "$C_RESET" "$RUN_ID"
  printf '%s  projeto: %s\n' "$C_DIM" "$RUN_NAME"
  printf '  backend: %s\n' "${BACKEND_PATH:-—}"
  printf '  frontend: %s\n' "${FRONTEND_PATH:-—}"
  printf '  alvo: %s\n' "${APP_URL:-${API_URL:-—}}"
  printf '  auth: %s\n' "$AUTH_MODE"
  printf '  dast: %s%s\n' "$(is_true "$ZAP_ACTIVE" && echo ativo || echo baseline)" "$C_RESET"

  # shellcheck source=./preflight.sh
  source "$DEVSEC_ROOT/lib/preflight.sh"
  # shellcheck source=./stack.sh
  source "$DEVSEC_ROOT/lib/stack.sh"
  # shellcheck source=./sast.sh
  source "$DEVSEC_ROOT/lib/sast.sh"
  # shellcheck source=./sca.sh
  source "$DEVSEC_ROOT/lib/sca.sh"
  # shellcheck source=./secrets.sh
  source "$DEVSEC_ROOT/lib/secrets.sh"
  # shellcheck source=./dast.sh
  source "$DEVSEC_ROOT/lib/dast.sh"

  run_preflight

  trap 'cleanup_dast_auth' EXIT
  application_up || true
  check_dast_targets

  stack_up || true

  if is_true "$ENABLE_SAST"; then run_sast; else record_status "sast" "skipped" "desabilitado" 0; fi
  if is_true "$ENABLE_SCA"; then run_sca; else record_status "sca" "skipped" "desabilitado" 0; fi
  if is_true "$ENABLE_SECRETS"; then run_secrets; else record_status "secrets" "skipped" "desabilitado" 0; fi
  if is_true "$ENABLE_DAST"; then run_dast; else record_status "dast" "skipped" "desabilitado" 0; fi

  run_meta_set "finished_at" "$(now_iso)"

  step "Relatório"
  local report_args=(--run-dir "$RUN_DIR")
  [[ -n "$baseline" ]] && report_args+=(--baseline "$baseline")
  python3 "$DEVSEC_ROOT/lib/report.py" "${report_args[@]}"

  local summary="$RUN_DIR/summary.json"
  if [[ -f "$summary" ]]; then
    printf '\n'
    printf '  %sID%s          %s\n' "$C_BOLD" "$C_RESET" "$RUN_ID"
    printf '  %sGate%s        %s\n' "$C_BOLD" "$C_RESET" "$(jq -r '.gate.result' "$summary")"
    printf '  %scritical%s    %s\n' "$C_BOLD" "$C_RESET" "$(jq -r '.counts.critical' "$summary")"
    printf '  %shigh%s        %s\n' "$C_BOLD" "$C_RESET" "$(jq -r '.counts.high' "$summary")"
    printf '  %smedium%s      %s\n' "$C_BOLD" "$C_RESET" "$(jq -r '.counts.medium' "$summary")"
    printf '  %slow%s         %s\n' "$C_BOLD" "$C_RESET" "$(jq -r '.counts.low' "$summary")"
    printf '  %sdashboard%s   %s\n' "$C_BOLD" "$C_RESET" "$RUN_DIR/index.html"
    printf '  %splano%s       %s\n' "$C_BOLD" "$C_RESET" "$RUN_DIR/remediation-plan.md"
    printf '  %sachados%s     %s\n' "$C_BOLD" "$C_RESET" "$RUN_DIR/findings.json"
  fi

  [[ "$open" == "1" ]] && open_report "$RUN_DIR/index.html"

  if [[ "${FAIL_ON_GATE:-0}" == "1" && -f "$summary" ]]; then
    case "$(jq -r '.gate.result' "$summary")" in
      FAIL) return 2 ;;
      REQUIRES_REVIEW) return 3 ;;
    esac
  fi
  return 0
}

resolve_run_dir() {
  local target="$1"
  if [[ -z "$target" || "$target" == "last" ]]; then
    local latest
    latest="$(ls -1dt "$DEVSEC_ROOT"/reports/runs/*/ 2>/dev/null | head -1 || true)"
    [[ -n "$latest" ]] || die "nenhuma execução encontrada em reports/runs"
    printf '%s' "${latest%/}"
  elif [[ -d "$target" ]]; then
    printf '%s' "$target"
  else
    printf '%s' "$DEVSEC_ROOT/reports/runs/$target"
  fi
}

cmd_report() {
  local run="last" baseline="" open=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run) run="${2:?--run exige um valor}"; shift 2 ;;
      --baseline) baseline="${2:?--baseline exige um valor}"; shift 2 ;;
      --open) open=1; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "opção desconhecida: $1" ;;
    esac
  done

  local run_dir
  run_dir="$(resolve_run_dir "$run")"
  [[ -d "$run_dir" ]] || die "execução não encontrada: $run"

  local args=(--run-dir "$run_dir")
  [[ -n "$baseline" ]] && args+=(--baseline "$baseline")
  python3 "$DEVSEC_ROOT/lib/report.py" "${args[@]}"

  ok "relatório regenerado: $run_dir/index.html"
  [[ "$open" == "1" ]] && open_report "$run_dir/index.html"
  return 0
}

cmd_list() {
  local dir="$DEVSEC_ROOT/reports/runs"
  [[ -d "$dir" ]] || { warn "nenhuma execução encontrada"; return 0; }

  printf '%-40s %-10s %5s %5s %5s %5s\n' "RUN" "GATE" "CRIT" "HIGH" "MED" "LOW"
  local run summary
  while IFS= read -r run; do
    [[ -z "$run" ]] && continue
    summary="$run/summary.json"
    if [[ -f "$summary" ]]; then
      printf '%-40s %-10s %5s %5s %5s %5s\n' \
        "$(basename "$run")" \
        "$(jq -r '.gate.result' "$summary")" \
        "$(jq -r '.counts.critical' "$summary")" \
        "$(jq -r '.counts.high' "$summary")" \
        "$(jq -r '.counts.medium' "$summary")" \
        "$(jq -r '.counts.low' "$summary")"
    else
      printf '%-40s %-10s\n' "$(basename "$run")" "—"
    fi
  done < <(ls -1dt "$dir"/*/ 2>/dev/null || true)
  return 0
}

cmd_clean() {
  local all=0
  [[ "${1:-}" == "--all" ]] && all=1
  local dir="$DEVSEC_ROOT/reports/runs"
  [[ -d "$dir" ]] || return 0

  local runs=()
  while IFS= read -r run; do
    [[ -n "$run" ]] && runs+=("$run")
  done < <(ls -1dt "$dir"/*/ 2>/dev/null || true)

  local keep=5
  [[ "$all" == "1" ]] && keep=0

  local i=0
  for run in "${runs[@]}"; do
    if [[ "$i" -ge "$keep" ]]; then
      rm -rf "$run"
      ok "removido: $(basename "$run")"
    fi
    i=$((i + 1))
  done
  return 0
}
