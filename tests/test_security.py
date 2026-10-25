import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import report
from dashboard import build_plan, render_dashboard


class Reports(unittest.TestCase):
    def test_no_coverage_never_passes(self):
        self.assertEqual(report.evaluate_gate([], [], 'critical,high')['result'], 'REQUIRES_REVIEW')
        skipped = [{'stage': s, 'status': 'skipped'} for s in ('sast', 'sca', 'secrets', 'dast')]
        self.assertEqual(report.evaluate_gate([], skipped, 'critical,high')['result'], 'REQUIRES_REVIEW')
        ok = [dict(s, status='ok') for s in skipped]
        self.assertEqual(report.evaluate_gate([], ok, 'critical,high')['result'], 'PASS')

    def test_dashboard_payload_cannot_close_script(self):
        attack = '</script><img src=x onerror=alert(1)>'
        finding = report.make_finding(source='semgrep', category='sast', severity='high', title=attack, evidence=attack)
        finding['id'] = 'F-0001'
        html = render_dashboard({}, [finding], build_plan([finding]))
        self.assertNotIn(attack, html)
        embedded = html.split('<script id="report-data" type="application/json">')[1].split('</script>')[0]
        self.assertEqual(json.loads(embedded)['findings'][0]['title'], attack)
        self.assertNotIn('innerHTML', html)

    def test_generation_with_scanner_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / 'raw/sast').mkdir(parents=True)
            (run / 'run.json').write_text(json.dumps({'project': 'fixture', 'run_id': 'test', 'scope': {}}))
            (run / 'raw/sast/status.json').write_text(json.dumps({'stage': 'sast', 'status': 'ok'}))
            (run / 'raw/sast/semgrep-backend.json').write_text(json.dumps({'results': [{
                'check_id': 'test.injection', 'path': 'src/test.py', 'start': {'line': 7},
                'extra': {'severity': 'ERROR', 'message': 'Unsafe query', 'metadata': {'cwe': ['CWE-89']}}
            }]}))
            self.assertEqual(report.main(['--run-dir', tmp]), 0)
            for name in ('index.html', 'report.html', 'report.md', 'findings.json', 'summary.json', 'context.md', 'remediation-plan.json', 'remediation-plan.md'):
                self.assertTrue((run / name).is_file(), name)
            plan = json.loads((run / 'remediation-plan.json').read_text())
            self.assertEqual(plan['items'][0]['finding_id'], 'F-0001')
            self.assertIn('regressão', plan['items'][0]['validation'])
            self.assertEqual(json.loads((run / 'summary.json').read_text())['gate']['result'], 'FAIL')

    def test_baseline_rejects_other_application(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a', Path(tmp) / 'b'
            a.mkdir(); b.mkdir()
            (a / 'run.json').write_text(json.dumps({'project': 'app-a', 'scope': {}}))
            (b / 'run.json').write_text(json.dumps({'project': 'app-b', 'scope': {}}))
            self.assertIn('error', report.compute_delta(str(a), [], str(b)))
            self.assertIsNone(report.resolve_baseline(str(a), 'last'))


class Orchestration(unittest.TestCase):
    def shell(self, code, directory):
        env = dict(os.environ, DEVSEC_ROOT=str(ROOT), RUN_DIR=directory)
        return subprocess.run(['bash', '-eu', '-c', code], env=env, text=True, capture_output=True)

    def test_analyze_selects_default_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/scan.sh"
cmd_scan() { printf '%s\\n' "$@"; }
cmd_analyze --open
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['--profile', str(ROOT / 'profiles/achernar-identity.env'), '--open'])

    def test_full_cli_generates_dashboard_without_running_scanners(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / 'bin', root / 'bin')
            shutil.copytree(ROOT / 'lib', root / 'lib', ignore=shutil.ignore_patterns('__pycache__'))
            (root / 'config').mkdir()
            (root / 'profiles').mkdir()
            (root / 'config/default-profile').write_text('profiles/test.env\n')
            (root / 'profiles/test.env').write_text('RUN_NAME=fixture\nENABLE_SAST=0\nENABLE_SCA=0\nENABLE_SECRETS=0\nENABLE_DAST=0\nSTACK_UP=0\nAPP_STACK_UP=0\n')
            fakebin = root / 'fakebin'
            fakebin.mkdir()
            docker = fakebin / 'docker'
            docker.write_text('#!/bin/sh\necho Unexpected_Docker_Execution >&2\nexit 99\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'], FAIL_ON_GATE='1')
            result = subprocess.run([str(root / 'bin/devsec'), 'analyze', '--run-id', 'test'], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 3, result.stderr)
            output = root / 'reports/runs/test'
            self.assertTrue((output / 'index.html').is_file())
            self.assertTrue((output / 'remediation-plan.md').is_file())
            self.assertNotIn('Unexpected_Docker_Execution', result.stderr)
            self.assertEqual(json.loads((output / 'summary.json').read_text())['gate']['result'], 'REQUIRES_REVIEW')

    def test_application_starts_before_target_check_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory(prefix='security test ') as tmp:
            script = '''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/stack.sh"
record_status() { :; }
docker() { printf '%s\\n' "$@" >> "$RUN_DIR/args"; }
APP_COMPOSE_FILE="$RUN_DIR/app compose.yml"
APP_COMPOSE_ENV_FILE="$RUN_DIR/test secrets.env"
APP_STACK_UP=1
mkdir -p "$RUN_DIR/logs"
application_up
[[ "$APP_STARTED" == 1 ]]
'''
            result = self.shell(script, tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = (Path(tmp) / 'args').read_text().splitlines()
            self.assertIn(str(Path(tmp) / 'app compose.yml'), args)
            self.assertIn(str(Path(tmp) / 'test secrets.env'), args)
            self.assertEqual(args[-3:], ['up', '-d', '--build'])

    def test_auth_failure_removes_temporary_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/dast.sh"
record_status() { printf '%s' "$2" > "$RUN_DIR/status"; }
build_zap_auth() { printf token > "$RUN_DIR/raw/dast/auth.prop"; return 1; }
mkdir -p "$RUN_DIR/raw/dast"
ENABLE_DAST=1 AUTH_REQUIRED=1
run_dast
[[ ! -e "$RUN_DIR/raw/dast/auth.prop" ]]
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(tmp) / 'status').read_text(), 'failed')

    def test_login_checks_protected_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/dast.sh"
mkdir -p "$RUN_DIR/raw/dast"
AUTH_USERNAME=fixture AUTH_PASSWORD=fixture AUTH_USE_COOKIE=1
AUTH_LOGIN_URL=http://localhost/login
AUTH_VERIFY_URL=http://localhost/session
run_meta_set() { printf '%s=%s' "$1" "$2" > "$RUN_DIR/verified"; }
curl() {
  local url="${!#}"
  if [[ "$url" == */login ]]; then
    printf '{}' > "$RUN_DIR/raw/dast/login-response.json"
    printf 'localhost\\tFALSE\\t/\\tFALSE\\t0\\tIDENTITY_SESSION\\tfixture\\n' > "$RUN_DIR/raw/dast/cookies.txt"
    printf '200'
  elif [[ " $* " == *" -b "* ]]; then
    printf '200'
  else
    printf '401'
  fi
}
dast_login
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(tmp) / 'verified').read_text(), 'auth_verified=true')

    def test_api_scan_is_passive_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/dast.sh"
mkdir -p "$RUN_DIR/raw/dast" "$RUN_DIR/logs"
printf '{}' > "$RUN_DIR/spec.json"
printf '{"site":[]}' > "$RUN_DIR/raw/dast/api.json"
API_URL=http://localhost:8080
OPENAPI_SPEC="$RUN_DIR/spec.json"
ZAP_ACTIVE=0
docker() { printf '%s\\n' "$@" > "$RUN_DIR/args"; }
zap_api
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = (Path(tmp) / 'args').read_text().splitlines()
            self.assertIn('-S', args)
            self.assertEqual(args[args.index('-f') + 1], 'openapi')
            self.assertEqual(args[args.index('-t') + 1], '/spec/spec.json')

    def test_unreachable_target_allows_report_with_failed_dast(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
source "$DEVSEC_ROOT/lib/common.sh"
source "$DEVSEC_ROOT/lib/stack.sh"
source "$DEVSEC_ROOT/lib/dast.sh"
curl() { return 7; }
record_status() { printf '%s' "$2" > "$RUN_DIR/status"; }
ENABLE_DAST=1
APP_URL=http://localhost:9999
check_dast_targets
run_dast
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(tmp) / 'status').read_text(), 'failed')


if __name__ == '__main__':
    unittest.main()
