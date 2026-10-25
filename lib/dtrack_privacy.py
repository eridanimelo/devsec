#!/usr/bin/env python3
"""Configura DTrack local: espelho OSV público, sem consultas por pacote."""
import json
import os
from pathlib import Path
import urllib.request
from network_policy import require_internal_url


def configure():
    require_internal_url(os.environ['DTRACK_URL'])
    base = os.environ['DTRACK_URL'].rstrip('/') + '/api/v1'
    headers = {'X-Api-Key': os.environ['DTRACK_API_KEY'], 'Content-Type': 'application/json'}

    def request(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None

    properties = request('/configProperty')
    index = {(p['groupName'], p['propertyName']): p for p in properties}
    settings = {('scanner', key): 'false' for key in (
        'ossindex.enabled', 'ossindex.alias.sync.enabled', 'npmaudit.enabled',
        'snyk.enabled', 'snyk.alias.sync.enabled', 'vulndb.enabled', 'trivy.enabled')}
    settings.update({('scanner', 'internal.enabled'): 'true',
                     ('vuln-source', 'google.osv.enabled'): 'Maven;npm',
                     ('vuln-source', 'google.osv.alias.sync.enabled'): 'false'})
    missing = set(settings) - set(index)
    if missing:
        raise RuntimeError('Propriedades não suportadas: ' + str(sorted(missing)))
    # Snapshot somente dos flags alterados; nunca salvar tokens/credenciais.
    audit = Path(os.environ['DEVSEC_ROOT']) / 'reports/dtrack-privacy'
    audit.mkdir(parents=True, exist_ok=True)
    before = [{'groupName': g, 'propertyName': n, 'propertyValue': index[g, n].get('propertyValue')}
              for g, n in settings]
    snapshot = audit / 'before.json'
    if not snapshot.exists():
        snapshot.write_text(json.dumps(before, indent=2))
    for (group, name), value in settings.items():
        if index[group, name].get('propertyValue') != value:
            request('/configProperty', {'groupName': group, 'propertyName': name, 'propertyValue': value,
                                       'propertyType': index[group, name]['propertyType']})
        print(group + '.' + name + '=' + value)
    repositories = request('/repository')
    changed = []
    for repository in repositories:
        if repository.get('enabled') and not repository.get('internal'):
            body = {k: repository[k] for k in ('uuid', 'type', 'identifier', 'url', 'resolutionOrder', 'internal', 'authenticationRequired', 'username') if k in repository}
            body['enabled'] = False
            request('/repository', body)
            changed.append(repository['identifier'])
    # Confirmar estado persistido, sem confiar somente no HTTP de atualização.
    actual = {(p['groupName'], p['propertyName']): p.get('propertyValue') for p in request('/configProperty')}
    assert all(actual[k] == v for k, v in settings.items()), 'Configuração não persistida'
    assert not any(r.get('enabled') and not r.get('internal') for r in request('/repository')), 'Repositório externo ainda habilitado'
    result = {'settings': [{'group': g, 'name': n, 'value': v} for (g, n), v in settings.items()],
              'external_repositories_disabled': changed, 'verified': True,
              'notice': 'Configuração funcional verificada; não equivale a auditoria de tráfego ou bloqueio de egress.'}
    (audit / 'applied.json').write_text(json.dumps(result, indent=2))
    print('Configuração persistida e verificada. Repositórios externos desabilitados:', len(changed))


if __name__ == '__main__':
    configure()
