from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import security_data
from network_policy import require_internal_url


class PublicUpdates(unittest.TestCase):
    def test_download_has_no_project_mounts_and_manifest_checks_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            calls = []
            def docker(*args, **kwargs):
                calls.append(tuple(map(str, args)))
                if args[:2] == ('image', 'inspect'):
                    return 'sha256:fixture'
                if 'status' in args:
                    return json.dumps({'valid': True, 'built': datetime.now(timezone.utc).isoformat()})
                return ''
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'rules: []'
            with patch.object(security_data, 'CACHE', cache), patch.object(security_data, 'docker', docker), patch.object(security_data.urllib.request, 'urlopen', return_value=response) as http:
                security_data.update()
                manifest = security_data.load_manifest()
                self.assertTrue(security_data.ready(manifest))
                old = json.loads(json.dumps(manifest))
                old['grype']['built'] = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
                self.assertFalse(security_data.ready(old))
                self.assertFalse(security_data.ready(manifest, datetime.now(timezone.utc) + timedelta(days=2)))
                (cache / 'rules.yaml').write_text('altered')
                self.assertFalse(security_data.ready(manifest))
            request = http.call_args_list[0].args[0]
            self.assertIsNone(request.data)
            self.assertEqual(request.full_url, 'https://semgrep.dev/c/p/owasp-top-ten')
            for call in calls:
                for arg in call:
                    if ':/rules:' in arg or ':/src:' in arg or ':/db' in arg:
                        self.assertTrue(arg.startswith(str(cache)))
                self.assertFalse(any(':/work' in arg or ':/repo' in arg for arg in call))
            validate = next(c for c in calls if '--entrypoint' in c)
            self.assertIn('--network=none', validate)
            self.assertIn('--network=none', validate)

    def test_invalid_db_does_not_publish_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            def docker(*args, **kwargs):
                if args[:2] == ('image', 'inspect'): return 'sha256:fixture'
                if 'status' in args: return '{"valid":false}'
                return ''
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'rules: []'
            with patch.object(security_data, 'CACHE', Path(directory)), patch.object(security_data, 'docker', docker), patch.object(security_data.urllib.request, 'urlopen', return_value=response):
                with self.assertRaises(RuntimeError): security_data.update()
                self.assertFalse((Path(directory) / 'manifest.json').exists())

    def test_only_approved_services_receive_project_data(self):
        require_internal_url('http://localhost:9081')
        for url in ('https://external.example', 'http://localhost@external.example', 'http://localhost/?token=secret'):
            with self.assertRaises(ValueError): require_internal_url(url)
        with patch.dict(os.environ, {'INTERNAL_SERVICE_HOSTS': 'dtrack.corp.internal'}):
            require_internal_url('https://dtrack.corp.internal')


if __name__ == '__main__':
    unittest.main()
