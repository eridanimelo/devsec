"""Allowlist explícita para serviços que recebem dados do projeto."""
import os
from urllib.parse import urlsplit


def require_internal_url(url):
    parsed = urlsplit(url)
    allowed = {'localhost', '127.0.0.1', '::1', 'host.docker.internal'}
    allowed.update(x.strip().lower() for x in os.environ.get('INTERNAL_SERVICE_HOSTS', '').split(',') if x.strip())
    if (parsed.scheme not in ('http', 'https') or parsed.hostname not in allowed
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Serviço fora da allowlist interna; configure INTERNAL_SERVICE_HOSTS somente com destinos corporativos aprovados')
