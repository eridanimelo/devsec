#!/usr/bin/env python3
"""Normaliza a saída bruta dos scanners e gera o relatório do devsec.

Lê `reports/runs/<run-id>/raw/**` e produz, no mesmo diretório:

  findings.json  — achados normalizados e deduplicados
  summary.json   — contagens, gate, delta e metadados
  report.md      — relatório legível
  report.html    — relatório autocontido (abre no navegador)
  context.md     — resumo compacto para a camada de IA (achernar_ia)

Uso:
  python3 lib/report.py --run-dir reports/runs/<id> [--baseline <id|last>]
"""

from __future__ import annotations

import argparse
from dashboard import build_plan, plan_markdown, render_dashboard
import glob
import hashlib
import html
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_RISK = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
SEV_LABEL = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "info": "Informativo",
}
CATEGORY_LABEL = {
    "sast": "SAST — análise estática",
    "sca": "SCA — dependências",
    "secret": "Segredos",
    "dast": "DAST — análise dinâmica",
}

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
OWASP_RE = re.compile(r"(A\d{2}:\d{4})", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# utilidades
# --------------------------------------------------------------------------- #

def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def dump_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def digest(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def norm_sev(value) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "critical": "critical",
        "crítico": "critical",
        "critico": "critical",
        "blocker": "critical",
        "high": "high",
        "alto": "high",
        "error": "high",
        "major": "medium",
        "medium": "medium",
        "médio": "medium",
        "medio": "medium",
        "warning": "medium",
        "low": "low",
        "baixo": "low",
        "minor": "low",
        "info": "info",
        "informational": "info",
        "information": "info",
        "note": "info",
        "none": "info",
    }
    return mapping.get(text, "info")


def norm_cwe(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    match = CWE_RE.search(text)
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"


def norm_owasp(value) -> str | None:
    if value is None:
        return None
    match = OWASP_RE.search(str(value))
    return match.group(1).upper() if match else None


def one_line(text, limit: int = 220) -> str:
    if text is None:
        return ""
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (str, int, float)):
        return [value]
    return []


def first(*values):
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def strip_component(component: str) -> str:
    """`run-backend:src/Foo.java` -> `src/Foo.java`."""
    if not component:
        return ""
    if ":" in component:
        return component.split(":", 1)[1]
    return component


def make_finding(
    *,
    source: str,
    category: str,
    severity: str,
    title: str,
    description: str = "",
    path: str | None = None,
    line=None,
    url: str | None = None,
    component: str | None = None,
    version: str | None = None,
    cwe=None,
    owasp=None,
    cvss=None,
    evidence: str = "",
    remediation: str = "",
    references=None,
    rule: str = "",
    confidence: str = "",
    fingerprint: str | None = None,
) -> dict:
    location = {"type": "file" if path else ("url" if url else "package")}
    if path:
        location["path"] = path
    if line not in (None, "", 0, "0"):
        try:
            location["line"] = int(line)
        except (TypeError, ValueError):
            pass
    if url:
        location["url"] = url
    if component:
        location["component"] = component
    if version:
        location["version"] = version

    return {
        "id": None,
        "fingerprint": fingerprint
        or digest(source, rule or title, path or url or "", line or "", component or ""),
        "source": source,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "title": one_line(title, 180),
        "description": one_line(description, 1200),
        "location": location,
        "cwe": [c for c in (norm_cwe(x) for x in as_list(cwe)) if c],
        "owasp": [o for o in (norm_owasp(x) for x in as_list(owasp)) if o],
        "cvss": cvss,
        "evidence": one_line(evidence, 500),
        "remediation": one_line(remediation, 800),
        "references": [str(r) for r in as_list(references)][:6],
        "rule": rule,
        "risk": SEV_RISK[severity],
    }


# --------------------------------------------------------------------------- #
# normalizadores
# --------------------------------------------------------------------------- #

def from_semgrep(path: str) -> list[dict]:
    data = load_json(path, {})
    out = []
    for item in data.get("results", []):
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        cwes = metadata.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        out.append(
            make_finding(
                source="semgrep",
                category="sast",
                severity=norm_sev(extra.get("severity")),
                title=item.get("check_id", "regra semgrep"),
                description=extra.get("message", ""),
                path=item.get("path"),
                line=(item.get("start") or {}).get("line"),
                cwe=cwes,
                owasp=metadata.get("owasp", []),
                evidence=(item.get("start") or {}).get("line") and extra.get("lines", ""),
                remediation=metadata.get("fix", "") or "",
                references=metadata.get("references", []),
                rule=item.get("check_id", ""),
                confidence=metadata.get("confidence", ""),
                fingerprint=extra.get("fingerprint")
                or digest("semgrep", item.get("check_id", ""), item.get("path", ""), (item.get("start") or {}).get("line", "")),
            )
        )
    return out


def from_sonar_issues(path: str) -> list[dict]:
    data = load_json(path, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        kind = str(item.get("type", "")).upper()
        if kind not in ("VULNERABILITY", "SECURITY_HOTSPOT", ""):
            continue
        component = strip_component(item.get("component", ""))
        line = item.get("line") or (item.get("textRange") or {}).get("startLine")
        out.append(
            make_finding(
                source="sonar",
                category="sast",
                severity=norm_sev(item.get("severity")),
                title=item.get("message", item.get("rule", "issue sonar")),
                description=item.get("message", ""),
                path=component,
                line=line,
                cwe=item.get("cwe", []),
                remediation="",
                references=[f"{item.get('rule', '')}"],
                rule=item.get("rule", ""),
                fingerprint=digest("sonar", item.get("rule", ""), component, line or ""),
            )
        )
    return out


def from_sonar_hotspots(path: str) -> list[dict]:
    data = load_json(path, [])
    if not isinstance(data, list):
        return []
    prob = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    out = []
    for item in data:
        component = strip_component(item.get("component", ""))
        line = item.get("line") or (item.get("textRange") or {}).get("startLine")
        sev = prob.get(str(item.get("vulnerabilityProbability", "")).upper(), "medium")
        out.append(
            make_finding(
                source="sonar",
                category="sast",
                severity=sev,
                title=item.get("message", item.get("ruleKey", "hotspot sonar")),
                description=item.get("message", ""),
                path=component,
                line=line,
                rule=item.get("ruleKey", ""),
                confidence=str(item.get("vulnerabilityProbability", "")).lower(),
                fingerprint=digest("sonar-hotspot", item.get("ruleKey", ""), component, line or ""),
            )
        )
    return out


def from_grype(path: str) -> list[dict]:
    data = load_json(path, {})
    out = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        version = artifact.get("version", "")
        component = artifact.get("name", "")
        fix = (vuln.get("fix") or {}).get("versions") or []
        cve = vuln.get("id", "")
        if fix:
            remediation = f"Atualizar {component} para {', '.join(fix)}."
        else:
            remediation = "Sem versão corrigida publicada; avaliar mitigação ou substituição."
        out.append(
            make_finding(
                source="grype",
                category="sca",
                severity=norm_sev(vuln.get("severity")),
                title=f"{cve} em {component}@{version}",
                description=vuln.get("description", ""),
                component=component,
                version=version,
                cvss=_extract_cvss(vuln),
                evidence=f"{component}@{version} ({artifact.get('type', 'desconhecido')})",
                remediation=remediation,
                references=vuln.get("urls", []),
                rule=cve,
                fingerprint=digest("sca", component, version, cve),
            )
        )
    return out


def from_dtrack(path: str) -> list[dict]:
    data = load_json(path, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        component = item.get("component", {}) or {}
        vuln = item.get("vulnerability", {}) or {}
        name = component.get("name", "")
        version = component.get("version", "")
        cve = first(vuln.get("vulnId"), vuln.get("id"), "")
        cwes = vuln.get("cwes", [])
        out.append(
            make_finding(
                source="dtrack",
                category="sca",
                severity=norm_sev(vuln.get("severity")),
                title=f"{cve} em {name}@{version}",
                description=vuln.get("description", ""),
                component=name,
                version=version,
                cwe=[f"CWE-{c}" if str(c).isdigit() else str(c) for c in as_list(cwes)],
                evidence=f"{name}@{version} — fonte: {vuln.get('source', 'NVD')}",
                remediation="Atualizar a dependência para uma versão sem a vulnerabilidade.",
                rule=cve,
                fingerprint=digest("sca", name, version, cve),
            )
        )
    return out


def from_gitleaks(path: str) -> list[dict]:
    data = load_json(path, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        evidence = first(item.get("Match"), item.get("Secret"), "")
        out.append(
            make_finding(
                source="gitleaks",
                category="secret",
                severity="high",
                title=f"Possível segredo exposto: {item.get('RuleID', 'regra')}",
                description=item.get("Description", "") or "Credencial detectada no código.",
                path=item.get("File", ""),
                line=item.get("StartLine"),
                evidence=evidence,
                remediation="Revogar a credencial, remover do código e usar variável de ambiente/segredo gerenciado.",
                rule=item.get("RuleID", ""),
                fingerprint=digest("secret", item.get("RuleID", ""), item.get("File", ""), item.get("StartLine", "")),
            )
        )
    return out


def from_zap(path: str) -> list[dict]:
    data = load_json(path, {})
    out = []
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or []
            inst = instances[0] if instances else {}
            url = inst.get("uri") or site.get("@name", "")
            url = str(url).replace("host.docker.internal", "localhost")
            param = inst.get("param") or ""
            sev = risk.get(str(alert.get("riskcode", "0")), "info")
            evidence = first(inst.get("evidence"), inst.get("attack"), inst.get("param"), "")
            refs = [line.strip() for line in str(alert.get("reference", "")).split("\n") if line.strip()]
            out.append(
                make_finding(
                    source="zap",
                    category="dast",
                    severity=sev,
                    title=alert.get("alert", "alerta ZAP"),
                    description=alert.get("desc", ""),
                    url=url,
                    cwe=[alert.get("cweid")] if str(alert.get("cweid", "0")) not in ("0", "-1") else [],
                    evidence=evidence,
                    remediation=alert.get("solution", ""),
                    references=refs,
                    rule=str(alert.get("pluginid", "")),
                    confidence=alert.get("confidence", ""),
                    fingerprint=digest("dast", alert.get("pluginid", ""), url, param),
                )
            )
    return out


def _extract_cvss(vuln: dict):
    for entry in vuln.get("cvss", []) or []:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        if isinstance(metrics, dict):
            score = metrics.get("baseScore")
            if isinstance(score, (int, float)):
                return score
        elif isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    score = metric.get("baseScore")
                    if isinstance(score, (int, float)):
                        return score
    return None


# --------------------------------------------------------------------------- #
# dedupe / correlação
# --------------------------------------------------------------------------- #

def dedupe(findings: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    order = []
    for finding in findings:
        key = finding["fingerprint"]
        if key not in merged:
            finding["sources"] = [finding["source"]]
            merged[key] = finding
            order.append(key)
            continue
        current = merged[key]
        current["sources"] = sorted(set(current.get("sources", []) + [finding["source"]]))
        if SEV_RANK[finding["severity"]] < SEV_RANK[current["severity"]]:
            current["severity"] = finding["severity"]
        current["cwe"] = sorted(set(current.get("cwe", []) + finding.get("cwe", [])))
        current["owasp"] = sorted(set(current.get("owasp", []) + finding.get("owasp", [])))
        for field in ("description", "remediation", "evidence", "cvss"):
            if not current.get(field) and finding.get(field):
                current[field] = finding[field]
    return [merged[key] for key in order]


def correlate(findings: list[dict]) -> None:
    groups: dict[tuple, list[dict]] = {}
    for finding in findings:
        loc = finding["location"]
        path, line = loc.get("path"), loc.get("line")
        if path and line:
            groups.setdefault((path, line), []).append(finding)
    for group in groups.values():
        if len({f["source"] for f in group}) < 2:
            continue
        for finding in group:
            finding["correlated_with"] = [
                other["id"] for other in group if other is not finding
            ]


# --------------------------------------------------------------------------- #
# coleta
# --------------------------------------------------------------------------- #

def collect(run_dir: str) -> tuple[list[dict], list[dict], dict]:
    findings: list[dict] = []
    run = load_json(os.path.join(run_dir, "run.json"), {})
    scope = run.get("scope", {})

    def add(items, project):
        for finding in items:
            finding["project"] = project
            finding["group"] = run.get("group") or run.get("project", "")
            # Mesma CVE/regra nos dois projetos são ocorrências independentes.
            finding["fingerprint"] = digest(project, finding["fingerprint"])
            findings.append(finding)

    scanners = (
        ("sast/semgrep-*.json", from_semgrep),
        ("sast/sonar-issues-*.json", from_sonar_issues),
        ("sast/sonar-hotspots-*.json", from_sonar_hotspots),
        ("sca/grype-*.json", from_grype),
        ("sca/dtrack-findings-*.json", from_dtrack),
        ("secrets/gitleaks-*.json", from_gitleaks),
    )
    for pattern, normalize in scanners:
        for path in sorted(glob.glob(os.path.join(run_dir, "raw", pattern))):
            project = next((name for name in ("frontend", "backend")
                            if os.path.basename(path).endswith("-" + name + ".json")), "shared")
            add(normalize(path), project)
    for path in sorted(glob.glob(os.path.join(run_dir, "raw/dast/*.json"))):
        if os.path.basename(path) in ("login-response.json", "playwright-headers.json"):
            continue
        for finding in from_zap(path):
            url = urlsplit(finding.get("location", {}).get("url", ""))
            app, api = urlsplit(scope.get("app_url") or ""), urlsplit(scope.get("api_url") or "")
            # Rotas /api no proxy do frontend pertencem ao backend.
            if scope.get("backend") and (url.netloc == api.netloc or
                    (url.netloc == app.netloc and (url.path == "/api" or url.path.startswith("/api/")))):
                owner = "backend"
            elif scope.get("frontend") and url.netloc == app.netloc:
                owner = "frontend"
            else:
                owner = "shared"
            add([finding], owner)

    statuses = []
    for path in sorted(glob.glob(os.path.join(run_dir, "raw/*/status.json"))):
        status = load_json(path, None)
        if isinstance(status, dict):
            statuses.append(status)

    findings = dedupe(findings)
    findings.sort(
        key=lambda f: (
            SEV_RANK[f["severity"]],
            -(f.get("cvss") or 0),
            f.get("title", ""),
        )
    )
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{index:04d}"
    correlate(findings)

    run = load_json(os.path.join(run_dir, "run.json"), {})
    return findings, statuses, run


# --------------------------------------------------------------------------- #
# delta
# --------------------------------------------------------------------------- #

def resolve_baseline(run_dir: str, baseline: str) -> str | None:
    if not baseline:
        return None
    root = os.path.dirname(os.path.abspath(run_dir))
    if baseline == "last":
        current = load_json(os.path.join(run_dir, "run.json"), {})
        candidates = sorted(
            (d for d in glob.glob(os.path.join(root, "*"))
             if os.path.isdir(d) and os.path.abspath(d) != os.path.abspath(run_dir)
             and load_json(os.path.join(d, "run.json"), {}).get("project") == current.get("project")
             and load_json(os.path.join(d, "run.json"), {}).get("scope") == current.get("scope")),
            key=os.path.getmtime,
            reverse=True,
        )
        return candidates[0] if candidates else None
    if os.path.isdir(baseline):
        return baseline
    path = os.path.join(root, baseline)
    return path if os.path.isdir(path) else None


def compute_delta(run_dir: str, findings: list[dict], baseline: str) -> dict | None:
    base_dir = resolve_baseline(run_dir, baseline)
    if not base_dir:
        return {"baseline": None, "error": f"baseline não encontrada: {baseline}"}

    current_run = load_json(os.path.join(run_dir, "run.json"), {})
    base_run = load_json(os.path.join(base_dir, "run.json"), {})
    if any(current_run.get(key) != base_run.get(key) for key in ("project", "scope", "dast")):
        return {"baseline": os.path.basename(base_dir), "error": "Projeto, escopo ou modo DAST incompatível; comparação omitida."}
    def coverage(directory):
        return {s.get("stage"): s.get("status") for s in
                (load_json(p, {}) for p in glob.glob(os.path.join(directory, "raw/*/status.json")))
                if s.get("stage") in ("sast", "sca", "secrets", "dast")}
    current_coverage, base_coverage = coverage(run_dir), coverage(base_dir)
    if current_coverage != base_coverage or any(v in ("failed", "partial") for v in current_coverage.values()):
        return {"baseline": os.path.basename(base_dir), "error": "Cobertura diferente ou incompleta; comparação omitida."}

    base_data = load_json(os.path.join(base_dir, "findings.json"), [])
    if not isinstance(base_data, list):
        return {"baseline": os.path.basename(base_dir), "error": "findings.json inválido"}

    current_fps = {f["fingerprint"] for f in findings}
    base_fps = {f["fingerprint"] for f in base_data}
    new = [f for f in findings if f["fingerprint"] not in base_fps]
    fixed = [f for f in base_data if f["fingerprint"] not in current_fps]
    return {
        "baseline": os.path.basename(base_dir),
        "new": len(new),
        "fixed": len(fixed),
        "persisting": len(findings) - len(new),
        "new_ids": [f["id"] for f in new][:50],
        "fixed_refs": [f.get("title", "") for f in fixed][:50],
    }


# --------------------------------------------------------------------------- #
# gate / sumário
# --------------------------------------------------------------------------- #

def evaluate_gate(findings: list[dict], statuses: list[dict], fail_on: str) -> dict:
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITIES}
    threshold = [s.strip().lower() for s in fail_on.split(",") if s.strip()]
    triggered = [sev for sev in threshold if counts.get(sev, 0) > 0]

    # Sem execução comprovada, nunca sinalizar PASS por ausência de achados.
    statuses = list(statuses)
    for stage in ('sast', 'sca', 'secrets', 'dast'):
        if not any(s.get('stage') == stage and s.get('status') == 'ok' for s in statuses):
            if not any(s.get('stage') == stage and s.get('status') in ('failed', 'partial') for s in statuses):
                statuses.append({'stage': stage, 'status': 'partial'})
    failed = [s for s in statuses if s.get("status") == "failed"]
    partial = [s for s in statuses if s.get("status") == "partial"]

    if triggered:
        result = "FAIL"
    elif failed or partial:
        result = "REQUIRES_REVIEW"
    else:
        result = "PASS"

    return {
        "result": result,
        "fail_on": threshold,
        "triggered_by": triggered,
        "failed_stages": [s.get("stage") for s in failed],
        "partial_stages": [s.get("stage") for s in partial],
    }


def build_summary(run_dir, findings, statuses, run, delta, gate) -> dict:
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITIES}
    counts["total"] = len(findings)

    by_category: dict[str, dict] = {}
    by_source: dict[str, int] = {}
    for finding in findings:
        category = finding["category"]
        by_category.setdefault(category, {sev: 0 for sev in SEVERITIES})
        by_category[category][finding["severity"]] += 1
        by_source[finding["source"]] = by_source.get(finding["source"], 0) + 1

    top = [
        {
            "id": f["id"],
            "severity": f["severity"],
            "title": f["title"],
            "category": f["category"],
            "source": f["source"],
            "location": f["location"],
            "cwe": f["cwe"],
        }
        for f in findings[:15]
    ]

    return {
        "run_id": run.get("run_id", os.path.basename(run_dir)),
        "project": run.get("project", ""),
        "group": run.get("group") or run.get("project", ""),
        "report_level": run.get("report_level", "group"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "scope": run.get("scope", {}),
        "dast": dict(run.get("dast", {}), auth_verified=run.get("auth_verified") == "true"),
        "counts": counts,
        "by_category": by_category,
        "by_source": by_source,
        "gate": gate,
        "tools": statuses,
        "limitations": run.get("limitations", []),
        "security_data": run.get("security_data", {}),
        "delta": delta,
        "top": top,
        "artifacts": {
            "dashboard": os.path.join(run_dir, "index.html"),
            "remediation_plan": os.path.join(run_dir, "remediation-plan.json"),
            "remediation_plan_md": os.path.join(run_dir, "remediation-plan.md"),
            "findings": os.path.join(run_dir, "findings.json"),
            "report_md": os.path.join(run_dir, "report.md"),
            "report_html": os.path.join(run_dir, "report.html"),
            "context_md": os.path.join(run_dir, "context.md"),
            "raw": os.path.join(run_dir, "raw"),
            "logs": os.path.join(run_dir, "logs"),
        },
    }


# --------------------------------------------------------------------------- #
# renderização markdown
# --------------------------------------------------------------------------- #

def md_cell(value, limit: int = 90) -> str:
    text = one_line(value, limit).replace("|", "\\|")
    return text or "—"


def location_text(finding: dict) -> str:
    loc = finding["location"]
    if loc.get("path"):
        return f"`{loc['path']}`" + (f":{loc['line']}" if loc.get("line") else "")
    if loc.get("url"):
        return f"`{one_line(loc['url'], 120)}`"
    if loc.get("component"):
        pkg = str(loc["component"]) + (f"@{loc['version']}" if loc.get("version") else "")
        return f"`{pkg}`"
    return "—"


def render_markdown(summary, findings) -> str:
    counts = summary["counts"]
    gate = summary["gate"]
    lines: list[str] = []

    lines.append(f"# Relatório de Segurança — {summary['project'] or summary['run_id']}")
    lines.append("")
    lines.append(f"**Run:** `{summary['run_id']}`  ")
    lines.append(f"**Gerado em:** {summary['generated_at']}  ")
    lines.append(f"**Gate:** `{gate['result']}`  ")
    scope = summary.get("scope", {})
    if scope.get("backend"):
        lines.append(f"**Backend:** `{scope['backend']}`  ")
    if scope.get("frontend"):
        lines.append(f"**Frontend:** `{scope['frontend']}`  ")
    if scope.get("app_url"):
        lines.append(f"**Alvo:** {scope['app_url']}  ")
    dast = summary.get("dast", {})
    if dast:
        lines.append(f"**DAST:** {dast.get('mode', '—')} · auth: {dast.get('auth_mode', '—')}  ")
    lines.append("")

    lines.append("## Resumo executivo")
    lines.append("")
    lines.append("| Severidade | Quantidade |")
    lines.append("|---|---:|")
    for sev in SEVERITIES:
        lines.append(f"| {SEV_LABEL[sev]} | {counts[sev]} |")
    lines.append(f"| **Total** | **{counts['total']}** |")
    lines.append("")
    if gate["result"] == "FAIL":
        lines.append(
            f"> **Gate FAIL** — limiar `{', '.join(gate['fail_on'])}`: "
            f"{', '.join(gate['triggered_by']) or '—'} encontrado(s)."
        )
    elif gate["result"] == "REQUIRES_REVIEW":
        lines.append("> **Gate REQUIRES_REVIEW** — há estágios incompletos ou com falha.")
    else:
        lines.append("> **Gate PASS** — nenhum achado acima do limiar e todos os estágios concluídos.")
    lines.append("")

    lines.append("## Cobertura da execução")
    lines.append("")
    lines.append("| Estágio | Status | Detalhe | Duração |")
    lines.append("|---|---|---|---:|")
    for status in summary.get("tools", []):
        lines.append(
            f"| {status.get('stage', '—')} | {status.get('status', '—')} | "
            f"{md_cell(status.get('detail', ''))} | {status.get('duration_s', 0)}s |"
        )
    lines.append("")

    top = [f for f in findings if f["severity"] in ("critical", "high")][:10]
    if top:
        lines.append("## Principais riscos")
        lines.append("")
        for finding in top:
            lines.append(f"### [{finding['id']}] {finding['title']} — {SEV_LABEL[finding['severity']]}")
            lines.append("")
            lines.append(f"- **Onde:** {location_text(finding)}")
            if finding["cwe"]:
                lines.append(f"- **CWE:** {', '.join(finding['cwe'])}")
            if finding["owasp"]:
                lines.append(f"- **OWASP:** {', '.join(finding['owasp'])}")
            if finding.get("cvss"):
                lines.append(f"- **CVSS:** {finding['cvss']}")
            if finding.get("sources"):
                lines.append(f"- **Fontes:** {', '.join(finding['sources'])}")
            if finding.get("description"):
                lines.append(f"- **Descrição:** {one_line(finding['description'], 400)}")
            if finding.get("evidence"):
                lines.append(f"- **Evidência:** `{one_line(finding['evidence'], 240)}`")
            if finding.get("remediation"):
                lines.append(f"- **Correção sugerida:** {one_line(finding['remediation'], 400)}")
            lines.append("")

    lines.append("## Achados por categoria")
    lines.append("")
    for category in ("sast", "sca", "secret", "dast"):
        items = [f for f in findings if f["category"] == category]
        lines.append(f"### {CATEGORY_LABEL[category]} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("Nenhum achado.")
            lines.append("")
            continue
        lines.append("| ID | Sev | Título | Local | Regra |")
        lines.append("|---|---|---|---|---|")
        for finding in items[:100]:
            lines.append(
                f"| {finding['id']} | {SEV_LABEL[finding['severity']]} | "
                f"{md_cell(finding['title'])} | {location_text(finding)} | "
                f"{md_cell(finding.get('rule', ''), 40)} |"
            )
        if len(items) > 100:
            lines.append(f"| … | | mais {len(items) - 100} achado(s) em `findings.json` | | |")
        lines.append("")

    lines.append("## Plano de correção")
    lines.append("")
    plan = {
        "Imediato (crítico e alto)": [f for f in findings if f["severity"] in ("critical", "high")],
        "Curto prazo (médio)": [f for f in findings if f["severity"] == "medium"],
        "Médio prazo (baixo e informativo)": [f for f in findings if f["severity"] in ("low", "info")],
    }
    for title, items in plan.items():
        lines.append(f"### {title}")
        lines.append("")
        if not items:
            lines.append("Nada a tratar nesta faixa.")
            lines.append("")
            continue
        for finding in items[:30]:
            action = finding.get("remediation") or finding.get("description") or "Revisar o achado e aplicar correção."
            lines.append(f"1. **[{finding['id']}]** {finding['title']} — {one_line(action, 240)}")
        if len(items) > 30:
            lines.append(f"1. … mais {len(items) - 30} item(ns); ver `findings.json`.")
        lines.append("")

    delta = summary.get("delta")
    if delta:
        lines.append("## Delta em relação à execução anterior")
        lines.append("")
        if delta.get("error"):
            lines.append(f"> {delta['error']}")
        else:
            lines.append(f"- Baseline: `{delta.get('baseline')}`")
            lines.append(f"- Novos: **{delta.get('new', 0)}**")
            lines.append(f"- Corrigidos: **{delta.get('fixed', 0)}**")
            lines.append(f"- Persistentes: **{delta.get('persisting', 0)}**")
        lines.append("")

    lines.append("## Limitações")
    lines.append("")
    lines.append("- Baseline do ZAP não cobre fluxos que exigem autenticação além do contexto configurado;")
    lines.append("- scans ativos só rodam com `--active` e autorização explícita;")
    lines.append("- SCA depende do SBOM; dependências não resolvidas pelo Syft não aparecem;")
    lines.append("- o Dependency-Track pode estar sem o espelho da NVD completo (o Grype cobre o intervalo);")
    lines.append("- resultado de ferramenta não substitui revisão humana de exploitabilidade.")
    lines.append("")

    lines.append("## Artefatos")
    lines.append("")
    for name, path in summary.get("artifacts", {}).items():
        lines.append(f"- **{name}:** `{path}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "> Execução local autorizada. Não use este pipeline contra alvos de terceiros sem autorização formal."
    )
    lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# renderização html
# --------------------------------------------------------------------------- #

HTML_CSS = """
:root{--bg:#0f1115;--card:#171a21;--line:#2a2f3a;--fg:#e7e9ee;--dim:#9aa3b2;
--crit:#e5484d;--high:#f76b15;--med:#f5b301;--low:#3b82f6;--info:#6b7280;--ok:#30a46c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
h3{font-size:15px;margin:24px 0 8px}
.meta{color:var(--dim);font-size:13px;margin-bottom:24px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}
.FAIL{background:rgba(229,72,77,.15);color:var(--crit);border:1px solid rgba(229,72,77,.4)}
.PASS{background:rgba(48,164,108,.15);color:var(--ok);border:1px solid rgba(48,164,108,.4)}
.REQUIRES_REVIEW{background:rgba(245,179,1,.15);color:var(--med);border:1px solid rgba(245,179,1,.4)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card .n{font-size:24px;font-weight:700}
.card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.critical .n{color:var(--crit)}.high .n{color:var(--high)}.medium .n{color:var(--med)}
.low .n{color:var(--low)}.info .n{color:var(--info)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
code{background:#11141a;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12px}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 7px;border-radius:999px}
.sev-critical{background:rgba(229,72,77,.15);color:var(--crit)}
.sev-high{background:rgba(247,107,21,.15);color:var(--high)}
.sev-medium{background:rgba(245,179,1,.15);color:var(--med)}
.sev-low{background:rgba(59,130,246,.15);color:var(--low)}
.sev-info{background:rgba(107,114,128,.2);color:var(--info)}
.finding{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.finding h4{margin:0 0 6px;font-size:14px}
.finding p{margin:4px 0;color:#c9ced9}
.dim{color:var(--dim)}
ul.plan{padding-left:18px}
footer{margin-top:48px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}}
"""


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def render_html(summary, findings) -> str:
    counts = summary["counts"]
    gate = summary["gate"]
    scope = summary.get("scope", {})
    dast = summary.get("dast", {})

    parts = [
        "<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Relatório de Segurança — {esc(summary['run_id'])}</title>",
        f"<style>{HTML_CSS}</style></head><body><main>",
        f"<h1>Relatório de Segurança — {esc(summary.get('project') or summary['run_id'])}</h1>",
        f"<div class='meta'>Run <code>{esc(summary['run_id'])}</code> · {esc(summary['generated_at'])} · "
        f"Gate <span class='badge {esc(gate['result'])}'>{esc(gate['result'])}</span></div>",
    ]

    if scope:
        scope_bits = []
        if scope.get("backend"):
            scope_bits.append(f"backend <code>{esc(scope['backend'])}</code>")
        if scope.get("frontend"):
            scope_bits.append(f"frontend <code>{esc(scope['frontend'])}</code>")
        if scope.get("app_url"):
            scope_bits.append(f"alvo <code>{esc(scope['app_url'])}</code>")
        if scope_bits:
            parts.append(f"<div class='meta'>{' · '.join(scope_bits)}</div>")
    if dast:
        parts.append(
            f"<div class='meta'>DAST {esc(dast.get('mode', '—'))} · auth {esc(dast.get('auth_mode', '—'))}</div>"
        )

    parts.append("<div class='cards'>")
    for sev in SEVERITIES:
        parts.append(
            f"<div class='card {sev}'><div class='n'>{counts[sev]}</div>"
            f"<div class='l'>{SEV_LABEL[sev]}</div></div>"
        )
    parts.append("</div>")

    if gate["result"] == "FAIL":
        parts.append(
            f"<p>Limiar <code>{esc(', '.join(gate['fail_on']))}</code> atingido por "
            f"<strong>{esc(', '.join(gate['triggered_by']) or '—')}</strong>.</p>"
        )
    elif gate["result"] == "REQUIRES_REVIEW":
        parts.append("<p>Há estágios incompletos ou com falha; o resultado exige revisão.</p>")
    else:
        parts.append("<p>Nenhum achado acima do limiar e todos os estágios concluídos.</p>")

    parts.append("<h2>Cobertura da execução</h2><table><thead><tr>"
                 "<th>Estágio</th><th>Status</th><th>Detalhe</th><th>Duração</th>"
                 "</tr></thead><tbody>")
    for status in summary.get("tools", []):
        parts.append(
            f"<tr><td>{esc(status.get('stage'))}</td><td>{esc(status.get('status'))}</td>"
            f"<td>{esc(status.get('detail'))}</td><td>{esc(status.get('duration_s', 0))}s</td></tr>"
        )
    parts.append("</tbody></table>")

    top = [f for f in findings if f["severity"] in ("critical", "high")][:10]
    if top:
        parts.append("<h2>Principais riscos</h2>")
        for finding in top:
            parts.append("<div class='finding'>")
            parts.append(
                f"<h4><span class='sev sev-{esc(finding['severity'])}'>{esc(SEV_LABEL[finding['severity']])}</span> "
                f"{esc(finding['id'])} — {esc(finding['title'])}</h4>"
            )
            parts.append(f"<p class='dim'>{esc(location_text(finding))}</p>")
            if finding.get("description"):
                parts.append(f"<p>{esc(one_line(finding['description'], 500))}</p>")
            if finding.get("evidence"):
                parts.append(f"<p><strong>Evidência:</strong> <code>{esc(one_line(finding['evidence'], 240))}</code></p>")
            if finding.get("remediation"):
                parts.append(f"<p><strong>Correção:</strong> {esc(one_line(finding['remediation'], 400))}</p>")
            if finding["cwe"] or finding["owasp"]:
                parts.append(
                    f"<p class='dim'>{esc(', '.join(finding['cwe']))} {esc(', '.join(finding['owasp']))}</p>"
                )
            parts.append("</div>")

    parts.append("<h2>Achados por categoria</h2>")
    for category in ("sast", "sca", "secret", "dast"):
        items = [f for f in findings if f["category"] == category]
        parts.append(f"<h3>{esc(CATEGORY_LABEL[category])} ({len(items)})</h3>")
        if not items:
            parts.append("<p class='dim'>Nenhum achado.</p>")
            continue
        parts.append("<table><thead><tr><th>ID</th><th>Sev</th><th>Título</th>"
                     "<th>Local</th><th>Regra</th></tr></thead><tbody>")
        for finding in items[:100]:
            parts.append(
                f"<tr><td>{esc(finding['id'])}</td>"
                f"<td><span class='sev sev-{esc(finding['severity'])}'>{esc(SEV_LABEL[finding['severity']])}</span></td>"
                f"<td>{esc(finding['title'])}</td><td><code>{esc(location_text(finding))}</code></td>"
                f"<td>{esc(finding.get('rule', ''))}</td></tr>"
            )
        parts.append("</tbody></table>")
        if len(items) > 100:
            parts.append(f"<p class='dim'>Mais {len(items) - 100} achado(s) em <code>findings.json</code>.</p>")

    parts.append("<h2>Plano de correção</h2>")
    plans = {
        "Imediato (crítico e alto)": [f for f in findings if f["severity"] in ("critical", "high")],
        "Curto prazo (médio)": [f for f in findings if f["severity"] == "medium"],
        "Médio prazo (baixo e informativo)": [f for f in findings if f["severity"] in ("low", "info")],
    }
    for title, items in plans.items():
        parts.append(f"<h3>{esc(title)}</h3>")
        if not items:
            parts.append("<p class='dim'>Nada a tratar nesta faixa.</p>")
            continue
        parts.append("<ul class='plan'>")
        for finding in items[:30]:
            action = finding.get("remediation") or finding.get("description") or "Revisar o achado."
            parts.append(f"<li><strong>{esc(finding['id'])}</strong> {esc(finding['title'])} — {esc(one_line(action, 260))}</li>")
        if len(items) > 30:
            parts.append(f"<li class='dim'>… mais {len(items) - 30} item(ns).</li>")
        parts.append("</ul>")

    delta = summary.get("delta")
    if delta:
        parts.append("<h2>Delta</h2>")
        if delta.get("error"):
            parts.append(f"<p class='dim'>{esc(delta['error'])}</p>")
        else:
            parts.append(
                f"<p>Baseline <code>{esc(delta.get('baseline'))}</code> · "
                f"novos <strong>{delta.get('new', 0)}</strong> · "
                f"corrigidos <strong>{delta.get('fixed', 0)}</strong> · "
                f"persistentes <strong>{delta.get('persisting', 0)}</strong></p>"
            )

    parts.append("<h2>Limitações</h2><ul class='plan'>")
    for item in (
        "Baseline do ZAP não cobre fluxos além do contexto autenticado configurado.",
        "Scans ativos só rodam com --active e autorização explícita.",
        "SCA depende do SBOM; dependências não resolvidas pelo Syft não aparecem.",
        "O Dependency-Track pode estar sem o espelho da NVD completo; o Grype cobre o intervalo.",
        "Resultado de ferramenta não substitui revisão humana de exploitabilidade.",
    ):
        parts.append(f"<li>{esc(item)}</li>")
    parts.append("</ul>")

    parts.append(
        "<footer>Execução local autorizada. Não use este pipeline contra alvos de terceiros "
        "sem autorização formal.</footer></main></body></html>"
    )
    return "".join(parts)


# --------------------------------------------------------------------------- #
# contexto para IA
# --------------------------------------------------------------------------- #

def render_context(summary, findings) -> str:
    counts = summary["counts"]
    gate = summary["gate"]
    lines = [
        f"# Contexto da execução — {summary['run_id']}",
        "",
        f"- Projeto: {summary.get('project') or '—'}",
        f"- Gate: **{gate['result']}** (limiar: {', '.join(gate['fail_on'])})",
        f"- Contagem: {counts['critical']} crítico(s), {counts['high']} alto(s), "
        f"{counts['medium']} médio(s), {counts['low']} baixo(s), {counts['info']} informativo(s)",
        "",
        "## Estágios",
        "",
    ]
    for status in summary.get("tools", []):
        lines.append(f"- {status.get('stage')}: {status.get('status')} — {status.get('detail', '')}")

    lines += ["", "## Top achados", ""]
    for finding in findings[:25]:
        loc = location_text(finding).replace("`", "")
        extra = f" · {', '.join(finding['cwe'])}" if finding["cwe"] else ""
        lines.append(
            f"- **[{finding['id']}] {finding['severity']}** — {finding['title']} "
            f"({loc}){extra}"
        )
    if len(findings) > 25:
        lines.append(f"- … mais {len(findings) - 25} achado(s) em `findings.json`.")

    lines += [
        "",
        "## Como continuar",
        "",
        "- Detalhe de um achado: ler o item correspondente em `findings.json` e o arquivo/URL apontado.",
        "- Correção: abrir intenção BACKEND/FRONTEND com o ID do achado como escopo (exige GATE-AUT).",
        "- Re-scan: `devsec scan --profile <perfil> --only dast` (ou sast, sca, secrets).",
        "- Plano: usar a skill `security-remediation`.",
        "",
        "## Artefatos",
        "",
    ]
    for name, path in summary.get("artifacts", {}).items():
        lines.append(f"- {name}: `{path}`")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def write_reports(run_dir, summary, findings):
    plan = build_plan(findings)
    plan.update(group=summary.get("group"), project=summary.get("project"), report_level=summary.get("report_level"))
    dump_json(os.path.join(run_dir, "remediation-plan.json"), plan)
    with open(os.path.join(run_dir, "remediation-plan.md"), "w", encoding="utf-8") as fh:
        fh.write(plan_markdown(plan))
    with open(os.path.join(run_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(render_dashboard(summary, findings, plan))

    dump_json(os.path.join(run_dir, "findings.json"), findings)
    dump_json(os.path.join(run_dir, "summary.json"), summary)

    with open(os.path.join(run_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_markdown(summary, findings))
    with open(os.path.join(run_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(summary, findings))
    with open(os.path.join(run_dir, "context.md"), "w", encoding="utf-8") as fh:
        fh.write(render_context(summary, findings))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Normaliza achados e gera o relatório do devsec.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--baseline", default="")
    parser.add_argument("--fail-on", default="")
    args = parser.parse_args(argv)

    run_dir = os.path.abspath(args.run_dir)
    if not os.path.isdir(run_dir):
        print(f"run-dir não encontrado: {run_dir}", file=sys.stderr)
        return 1

    findings, statuses, run = collect(run_dir)
    run["security_data"] = load_json(os.path.join(run_dir, "security-data.json"), {})
    assessment = load_json(os.path.join(run_dir, "assessment.json"), {})
    if isinstance(assessment, dict):
        run["limitations"] = assessment.get("limitations", [])
    reviews = load_json(os.path.join(run_dir, "triage.json"), {})
    if isinstance(reviews, dict):
        for finding in findings:
            review = reviews.get(finding["fingerprint"])
            if isinstance(review, dict):
                finding["review"] = {k: str(review[k]) for k in ("status", "rationale", "action") if k in review}
    fail_on = args.fail_on or run.get("gate_fail_on") or os.environ.get("GATE_FAIL_ON", "critical,high")
    gate = evaluate_gate(findings, statuses, fail_on)
    delta = compute_delta(run_dir, findings, args.baseline) if args.baseline else None
    summary = build_summary(run_dir, findings, statuses, run, delta, gate)

    group = run.get("group") or run.get("project", "")
    summary["group"] = group
    summary["project"] = group
    projects = []
    for project in ("frontend", "backend"):
        items = [f for f in findings if f.get("project") == project]
        if not run.get("scope", {}).get(project) and not items:
            continue
        project_dir = os.path.join(run_dir, "projects", project)
        os.makedirs(project_dir, exist_ok=True)
        project_scope = {project: run.get("scope", {}).get(project)}
        url_key = "app_url" if project == "frontend" else "api_url"
        project_scope[url_key] = run.get("scope", {}).get(url_key)
        project_run = dict(run, group=group, project=project, report_level="project", scope=project_scope)
        # Os scanners atuais registram status por estágio do grupo. Não atribuir
        # sucesso individual quando a execução do grupo foi parcial.
        project_statuses = [dict(status, coverage_scope="group",
            detail=status.get("detail", "") + " (status herdado da execução do grupo)") for status in statuses]
        child = build_summary(project_dir, items, project_statuses, project_run, None,
                              evaluate_gate(items, project_statuses, fail_on))
        child["parent_dashboard"] = "../../index.html"
        child["artifacts"]["raw"] = os.path.join(run_dir, "raw")
        child["artifacts"]["logs"] = os.path.join(run_dir, "logs")
        write_reports(project_dir, child, items)
        projects.append({"name": project, "counts": child["counts"], "gate": child["gate"]["result"],
                         "dashboard": "projects/" + project + "/index.html"})
    summary["projects"] = projects
    write_reports(run_dir, summary, findings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
