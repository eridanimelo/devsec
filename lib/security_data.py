"""Download público sem montar código/SBOM; scanners usam cache sem rede."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

IMAGES = {'semgrep': 'semgrep/semgrep:latest', 'grype': 'ghcr.io/anchore/grype:latest',
          'syft': 'ghcr.io/anchore/syft:latest', 'gitleaks': 'zricethezav/gitleaks:latest'}
ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/security'


def docker(*args, capture=False):
    # Não propagar tokens/segredos do perfil a processos de atualização.
    env = {k: v for k, v in os.environ.items() if k in (
        'PATH', 'HOME', 'TMPDIR', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
        'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    return subprocess.run(['docker', *map(str, args)], check=True, env=env,
                          text=True, stdout=subprocess.PIPE if capture else None).stdout


def load_manifest():
    try:
        return json.loads((CACHE / 'manifest.json').read_text())
    except (OSError, ValueError):
        return {}


def ready(manifest, now=None):
    try:
        updated = datetime.fromisoformat(manifest['updated_at'])
        age = ((now or datetime.now(timezone.utc)) - updated).total_seconds()
        db_built = datetime.fromisoformat(manifest['grype']['built'].replace('Z', '+00:00'))
        db_age = ((now or datetime.now(timezone.utc)) - db_built).total_seconds()
        path = CACHE / 'rules.yaml'
        return (0 <= age < 86400 and manifest['grype'].get('valid') is True
                and 0 <= db_age <= 120 * 3600 and path.is_file()
                and hashlib.sha256(path.read_bytes()).hexdigest() == manifest['rules']['sha256']
                and (CACHE / 'grype').is_dir()
                and all(manifest.get('images', {}).get(k, {}).get('id') for k in IMAGES))
    except (KeyError, ValueError, TypeError):
        return False


def update(force=False):
    CACHE.mkdir(parents=True, exist_ok=True)
    if not force and ready(load_manifest()):
        print('Bases verificadas há menos de 24h; reutilizando cache local.')
        return
    # Downloader monta apenas cache; nunca diretórios do projeto, SBOM ou reports.
    images = {}
    for name, image in IMAGES.items():
        try:
            image_id = docker('image', 'inspect', '--format', '{{.Id}}', image, capture=True).strip()
        except subprocess.CalledProcessError:
            docker('pull', image)
            image_id = docker('image', 'inspect', '--format', '{{.Id}}', image, capture=True).strip()
        images[name] = {'reference': image, 'id': image_id}
    rules_url = 'https://semgrep.dev/c/p/owasp-top-ten'
    req = urllib.request.Request(rules_url, headers={'User-Agent': 'AchernarSecurity-PublicUpdater/1'})
    with urllib.request.urlopen(req, timeout=60) as response:
        content = response.read(20_000_001)
    if not content or len(content) > 20_000_000:
        raise RuntimeError('Tamanho de regras inválido')
    candidate = CACHE / 'rules.pending.yaml'
    candidate.write_bytes(content)
    # `semgrep --validate` baixa metarregras implicitamente. Baixá-las aqui,
    # antes, e chamar o engine diretamente mantém a validação sem rede.
    lint_url = 'https://semgrep.dev/c/p/semgrep-rule-lints'
    with urllib.request.urlopen(urllib.request.Request(lint_url, headers={
            'User-Agent': 'AchernarSecurity-PublicUpdater/1'}), timeout=60) as response:
        lint_content = response.read(20_000_001)
    if not lint_content or len(lint_content) > 20_000_000:
        raise RuntimeError('Metarregras inválidas')
    (CACHE / 'rule-lints.yaml').write_bytes(lint_content)
    validator = ("from semgrep.semgrep_core import SemgrepCore;import subprocess,json,sys;"
                 "p=subprocess.run([SemgrepCore.executable_path(),'-json','-check_rules',"
                 "'/rules/rule-lints.yaml','/rules/rules.pending.yaml'],capture_output=True,text=True);"
                 "sys.stdout.write(p.stdout);sys.stderr.write(p.stderr);"
                 "sys.exit(1 if p.returncode or json.loads(p.stdout[p.stdout.find('{'):]).get('errors') else 0)")
    docker('run', '--rm', '--pull=never', '--network=none', '--entrypoint', 'python',
           '-v', f'{CACHE}:/rules:ro', images['semgrep']['id'], '-c', validator)
    grype_dir = CACHE / 'grype'
    grype_dir.mkdir(exist_ok=True)
    docker('run', '--rm', '--pull=never', '-v', f'{grype_dir}:/db',
           '-e', 'GRYPE_DB_CACHE_DIR=/db', '-e', 'GRYPE_CHECK_FOR_APP_UPDATE=false',
           images['grype']['id'], 'db', 'update')
    raw = docker('run', '--rm', '--pull=never', '--network=none', '-v', f'{grype_dir}:/db',
                 '-e', 'GRYPE_DB_CACHE_DIR=/db', '-e', 'GRYPE_DB_AUTO_UPDATE=false',
                 '-e', 'GRYPE_CHECK_FOR_APP_UPDATE=false', images['grype']['id'],
                 'db', 'status', '-o', 'json', capture=True)
    db_status = json.loads(raw)
    if db_status.get('valid') is not True:
        raise RuntimeError('Base Grype inválida; análise não autorizada com esse cache')
    candidate.replace(CACHE / 'rules.yaml')
    manifest = {'updated_at': datetime.now(timezone.utc).isoformat(),
                'rules': {'source': rules_url, 'sha256': hashlib.sha256(content).hexdigest(),
                          'metarules_sha256': hashlib.sha256(lint_content).hexdigest()},
                'grype': db_status, 'images': images,
                'scan_network': 'none for semgrep, grype, syft, gitleaks'}
    pending = CACHE / 'manifest.pending.json'
    pending.write_text(json.dumps(manifest, indent=2))
    pending.replace(CACHE / 'manifest.json')
    print('Regras e base Grype atualizadas e validadas; manifesto salvo no cache local.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('update', 'status'))
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    if args.command == 'status':
        manifest = load_manifest()
        print(json.dumps({'ready': ready(manifest), **manifest}, indent=2))
        return 0 if ready(manifest) else 1
    update(args.force)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print('Atualização incompleta: ' + str(error), file=sys.stderr)
        sys.exit(1)
