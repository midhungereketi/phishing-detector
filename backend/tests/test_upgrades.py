import hashlib
import io
import json
import time
import zipfile
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.detector import Detector, finalize
from backend.evaluate import evaluate_csv
from backend.features import domain_group
from backend.intelligence import Intelligence, digest
from backend.network import UnsafeTarget, observe, public_addresses, public_request
from backend.storage import DEFAULT_SETTINGS


@pytest.fixture
def service(tmp_path):
    return Intelligence(tmp_path / 'intel.sqlite3')


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / 'users.sqlite3', tmp_path / 'intel.sqlite3'), headers={'X-PhishGuard': '1'}) as client:
        client.post('/api/auth/register', json={'username': 'upgrader', 'password': 'UpgradeTest!123'})
        yield client


@pytest.mark.parametrize('host', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '192.0.2.1', '::1', '::ffff:127.0.0.1', 'fc00::1'])
def test_private_reserved_and_mapped_addresses_refused(host):
    with pytest.raises(UnsafeTarget):
        public_addresses(host)


def test_mixed_public_private_dns_answer_refused(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = [['8.8.8.8', '10.0.0.1'], ['2606:4700:4700::1111']]
    monkeypatch.setattr('backend.network.dns.resolver.Resolver', lambda: resolver)
    with pytest.raises(UnsafeTarget):
        public_addresses('example.org')


@pytest.mark.parametrize('url', ['https://user:secret@example.org/', 'http://example.org:8080/'])
def test_credentials_and_nonstandard_ports_refused_before_dns(url, monkeypatch):
    resolver = Mock()
    monkeypatch.setattr('backend.network.public_addresses', resolver)
    with pytest.raises(UnsafeTarget):
        public_request(url)
    resolver.assert_not_called()


def test_dns_rebinding_redirect_revalidated_and_socket_pinned(monkeypatch):
    addresses = Mock(side_effect=[['8.8.8.8'], UnsafeTarget('private redirect')])
    monkeypatch.setattr('backend.network.public_addresses', addresses)
    sock = Mock()
    monkeypatch.setattr('backend.network.socket.socket', lambda *args: sock)
    response = Mock(status=302)
    response.getheader.return_value = 'http://10.0.0.1/'
    connection = Mock(sock=sock)
    connection.getresponse.return_value = response
    def connect():
        connection._create_connection(('example.org', 80), 3)
    connection.connect.side_effect = connect
    monkeypatch.setattr('backend.network.http.client.HTTPConnection', lambda *args, **kwargs: connection)
    with pytest.raises(UnsafeTarget):
        public_request('http://example.org/')
    sock.connect.assert_called_once_with(('8.8.8.8', 80))
    assert addresses.call_count == 2
    connection.request.assert_called_once()


def test_network_failure_is_not_a_clean_verdict(monkeypatch):
    monkeypatch.setattr('backend.network.public_request', Mock(side_effect=TimeoutError()))
    assert observe('https://example.org/')['status'] == 'unavailable'


def test_successful_network_observation_preserves_status_contract(monkeypatch):
    monkeypatch.setattr('backend.network.public_request', Mock(return_value={'url': 'http://example.org/', 'status': 200, 'certificate': None, 'body': b'', 'chain': [{'url': 'http://example.org/', 'status': 200, 'addresses': ['8.8.8.8']}]}))
    result = observe('http://example.org/')
    assert result['status'] == 'observed' and result['http_status'] == 200
    assert result['tls']['status'] == 'absent'


def test_feed_exact_match_fragment_normalization_stale_and_failed_import(service):
    row = {'url': 'https://www.example.org/pay?x=1', 'phish_id': 123, 'verified': 'yes', 'online': 'yes'}
    service.import_feed([row])
    assert service.lookup(row['url'] + '#anchor')['status'] == 'match'
    assert service.lookup('https://www.example.org/pay?x=2')['status'] == 'no_match'
    assert service.lookup('https://www.example.org/')['status'] == 'no_match'
    assert service.status()['status'] == 'fresh'
    with pytest.raises(ValueError):
        service.import_feed([{**row, 'verified': 'no'}])
    assert service.status()['entries'] == 1
    service.import_feed([row], updated=time.time() - 90000)
    assert service.lookup(row['url'])['cache_status'] == 'stale'
    assert digest(row['url']) == digest(row['url'] + '#anchor')


def test_feed_lookup_enforces_policy_in_app_and_extension(client):
    url = 'https://www.wikipedia.org/'
    client.app.state.intelligence.import_feed([{'url': url, 'phish_id': 123, 'verified': 'yes', 'online': 'yes'}])
    report = client.post('/api/scan/url', json={'url': url}).json()
    assert report['model_score'] < 30 and report['score'] == 95
    assert report['risk_level'] == 'High' and report['policy_reasons']
    assert client.post('/api/link-access', json={'url': url}).json()['allowed'] is False
    token = client.post('/api/extension/pair').json()['token']
    result = client.post('/api/extension/check', json={'url': url}, headers={'Authorization': 'Bearer ' + token}).json()
    assert result['risk_level'] == 'High'


def test_optional_vt_key_is_never_exposed_and_missing_lookup_explicit(service, monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    assert service.virustotal('https://example.org')['status'] == 'not_configured'
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'sensitive-test-key')
    request = Mock(return_value={'status': 200, 'body': json.dumps({'data': {'attributes': {'last_analysis_stats': {'malicious': 3}, 'last_analysis_date': int(time.time())}}}).encode()})
    monkeypatch.setattr('backend.intelligence.public_request', request)
    result = service.virustotal('https://example.org')
    assert result['counts']['malicious'] == 3
    assert 'sensitive-test-key' not in json.dumps(result)
    assert service.virustotal('https://example.org')['cached'] is True
    request.assert_called_once()
    assert service.virustotal('https://other.org')['status'] == 'rate_limited'


def test_cached_reputation_is_used_by_offline_access_checks(client):
    url = 'https://www.wikipedia.org/'
    service = client.app.state.intelligence
    service.cache[digest(url)] = (time.time(), {'status': 'observed', 'fresh': True, 'counts': {'malicious': 3}})
    assert client.post('/api/link-access', json={'url': url}).json()['allowed'] is False


def test_saved_redirect_warning_cannot_be_bypassed_by_offline_rescan(client, monkeypatch):
    url = 'https://www.wikipedia.org/'
    observed = {'status': 'observed', 'chain': [{'url': url}, {'url': 'http://192.0.2.15/verify/account'}]}
    monkeypatch.setattr('backend.intelligence.observe', lambda value: observed)
    monkeypatch.setattr('backend.intelligence.registration', lambda value: {'status': 'unknown'})
    report = client.post('/api/scan/url', json={'url': url, 'network_checks': True}).json()
    assert report['risk_level'] == 'High'
    client.post('/api/scan/url', json={'url': url})
    assert client.post('/api/link-access', json={'url': url}).json()['allowed'] is False
    monkeypatch.setattr('backend.intelligence.observe', lambda value: {'status': 'observed', 'chain': [{'url': url}]})
    client.post('/api/scan/url', json={'url': url, 'network_checks': True})
    assert client.post('/api/link-access', json={'url': url}).json()['allowed'] is True


def test_policy_scores_redirects_and_stale_provider_reports():
    report = {'kind': 'url', 'url': 'https://example.org/', 'host': 'example.org', 'model_score': 1, 'redirects': [{'host': 'evil.org', 'model_score': 90}]}
    assert finalize(report, DEFAULT_SETTINGS, set())['score'] == 90
    assert finalize(report, DEFAULT_SETTINGS, {'evil.org'})['score'] == 100
    report = {'kind': 'url', 'host': 'example.org', 'model_score': 1, 'reputation': {'status': 'observed', 'fresh': False, 'counts': {'malicious': 10}}}
    assert finalize(report, DEFAULT_SETTINGS, set())['score'] == 1


def test_eml_bytes_preserve_mime_encoding_and_reject_oversize(client):
    raw = b'From: team@college.example\r\nSubject: =?iso-8859-1?Q?R=E9union_de_projet?=\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nR\xe9union de notre groupe vendredi pour pr\xe9parer la pr\xe9sentation.'
    report = client.post('/api/scan/email-file', content=raw, headers={'Content-Type': 'message/rfc822'}).json()
    assert report['input_method'] == 'eml_file' and report['subject'] == 'Réunion de projet'
    assert 'raw' not in report
    assert client.post('/api/scan/email-file', content=b'x' * 300001, headers={'Content-Type': 'message/rfc822'}).status_code == 413
    assert client.post('/api/scan/email-file', content=b'anything', headers={'Content-Type': 'text/html'}).status_code == 415


def test_scoped_extension_tokens_revocation_and_no_account_privileges(client):
    token = client.post('/api/extension/pair').json()['token']
    headers = {'Authorization': 'Bearer ' + token}
    client.post('/api/blocklist', json={'host': 'www.wikipedia.org'})
    assert client.get('/api/extension/blocklist', headers=headers).json()['hosts'] == ['www.wikipedia.org']
    assert client.post('/api/extension/check', json={'url': 'https://www.wikipedia.org'}, headers=headers).json()['blocked_hosts']
    client.post('/api/auth/logout')
    assert client.get('/api/history', headers=headers).status_code == 401
    assert client.get('/api/settings', headers=headers).status_code == 401
    assert client.get('/api/extension/blocklist', headers=headers).status_code == 200
    client.post('/api/auth/login', json={'username': 'upgrader', 'password': 'UpgradeTest!123'})
    client.delete('/api/extension/pair')
    assert client.get('/api/extension/blocklist', headers=headers).status_code == 401


def test_extension_zip_contains_runnable_sources_and_no_secrets(client):
    response = client.get('/api/extension/download')
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        assert 'phishguard-extension/manifest.json' in names
        assert not any('.env' in name or '.sqlite' in name for name in names)
        manifest = json.loads(archive.read('phishguard-extension/manifest.json'))
        assert manifest['manifest_version'] == 3


def test_calibration_and_external_evaluation_exclude_corpus_domains():
    detector = Detector()
    assert detector.url.get('calibrated') and detector.email.get('calibrated')
    for kind in ('url', 'email'):
        model = detector.metadata[kind]
        assert model['calibration_samples'] > 0
        assert model['metrics']['thresholds'] and 0 <= model['metrics']['brier_score'] <= 1
    # Reserved example domains are synthetic fixtures, never claimed as a benchmark.
    csv = 'url,label\n' + '\n'.join(f'https://test{i}.example/path,{i % 2}' for i in range(12))
    detector.url['dataset_domains'].add(hashlib.sha256(domain_group('test0.example').encode()).hexdigest())
    result = evaluate_csv(csv, detector, 'Synthetic validation fixture')
    assert result['excluded']['overlapping_domain'] == 1
    assert result['metrics']['test_samples'] == 11
    with pytest.raises(ValueError):
        evaluate_csv('url,label\nhttps://example.org,1', detector, 'Invalid tiny dataset')


def test_evaluation_reports_are_user_scoped_and_do_not_change_models(client):
    csv = 'url,label\n' + '\n'.join(f'https://fixture{i}.example/path,{i % 2}' for i in range(12))
    response = client.post('/api/evaluation/urls', json={'csv': csv, 'source': 'Synthetic test only'})
    assert response.status_code == 200
    assert client.get('/api/evaluation').json()[0]['source'] == 'Synthetic test only'
    client.post('/api/auth/logout')
    client.post('/api/auth/register', json={'username': 'otheruser', 'password': 'UpgradeTest!123'})
    assert client.get('/api/evaluation').json() == []
