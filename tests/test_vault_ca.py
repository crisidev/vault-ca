import os
import json
import datetime

import pytest
import OpenSSL
import requests
import requests_mock

import vault_ca
from vault_ca import VaultCA, VaultCAError


@pytest.fixture
def vault_ca_obj(tmpdir):
    temp_dir = str(tmpdir)
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
        'bootstrap_ca': False,
        'ssl_verify': True,
        'output_dir': temp_dir,
        'ca_path': temp_dir
    }
    return VaultCA(kwargs)


@pytest.fixture
def vault_ca_obj_bootstap_ca(tmpdir):
    temp_dir = str(tmpdir)
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
        'bootstrap_ca': True,
        'output_dir': temp_dir,
        'ca_path': temp_dir
    }
    return VaultCA(kwargs)


def test_validate_args_ok():
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
    }
    ca = VaultCA(kwargs)
    assert ca.component == 'acomponent'
    assert ca.domain == 'test.org'
    assert ca.vault_token == 'atoken'


def test_validate_args_ko():
    kwargs = {
        'component': 'acomponent',
        'vault_token': 'atoken',
    }
    with pytest.raises(VaultCAError):
        VaultCA(kwargs)

    kwargs = {
        'domain': 'test.org',
        'vault_token': 'atoken',
    }
    with pytest.raises(VaultCAError):
        VaultCA(kwargs)


def test_manager_args(tmpdir):
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
        'bootstrap_ca': False,
        'ssl_verify': True,
        'output_dir': str(tmpdir),
        'valid_interval': 2
    }
    ca = VaultCA(kwargs)
    assert ca.component == 'acomponent'
    assert ca.domain == 'test.org'
    assert ca.vault_token == 'atoken'
    assert not ca.bootstrap_ca
    assert ca.ssl_verify
    assert os.path.isdir(ca.output_dir)
    assert ca.vault_address == 'https://vault.test.org:8200'
    assert ca.valid_interval == 2


def test_manager_args_bootstrap_ca(tmpdir):
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
        'bootstrap_ca': True,
        'output_dir': str(tmpdir),
    }
    ca = VaultCA(kwargs)
    assert ca.component == 'acomponent'
    assert ca.domain == 'test.org'
    assert ca.vault_token == 'atoken'
    assert ca.bootstrap_ca
    assert not ca.ssl_verify
    assert os.path.isdir(ca.output_dir)
    assert ca.vault_address == 'https://vault.test.org:8200'
    assert ca.valid_interval == 1


def test_make_dirs(vault_ca_obj, tmpdir):
    temp_dir = str(tmpdir)
    vault_ca_obj._make_dirs(os.path.join(temp_dir, 'atest'))
    assert os.path.isdir(os.path.join(temp_dir, 'atest'))
    # test it second time to increase the coverage
    vault_ca_obj._make_dirs(os.path.join(temp_dir, 'atest'))
    assert os.path.isdir(os.path.join(temp_dir, 'atest'))


def test_parse_asn1_generalizedtime_ok(vault_ca_obj):
    timestamp = '20220510141643Z'
    parsed_timestamp = vault_ca_obj._parse_asn1_generalizedtime(timestamp)
    assert parsed_timestamp.year == 2022
    assert parsed_timestamp.month == 5
    assert parsed_timestamp.day == 10
    assert parsed_timestamp.hour == 14
    assert parsed_timestamp.minute == 16
    assert parsed_timestamp.second == 43


def test_parse_asn1_generalizedtime_ko(vault_ca_obj):
    timestamp = '20220510141643'
    with pytest.raises(VaultCAError):
        vault_ca_obj._parse_asn1_generalizedtime(timestamp)
    timestamp = 'astring'
    with pytest.raises(VaultCAError):
        vault_ca_obj._parse_asn1_generalizedtime(timestamp)
    timestamp = ''
    with pytest.raises(VaultCAError):
        vault_ca_obj._parse_asn1_generalizedtime(timestamp)


def test_load_certificate_ok(vault_ca_obj):
    pem = vault_ca_obj._load_certificate('tests/fixtures/acomponent-test.test.org.pem.ok')
    assert pem.get_signature_algorithm() == b'sha256WithRSAEncryption'


def test_load_certificate_ko(vault_ca_obj):
    with pytest.raises(VaultCAError):
        vault_ca_obj._load_certificate('tests/fixtures/acomponent-test.test.org.pem.ko')


def test_load_certificate_empty(vault_ca_obj):
    with pytest.raises(VaultCAError):
        vault_ca_obj._load_certificate('tests/fixtures/acomponent-test.test.org.pem.empty')


def test_is_certificate_valid_true(vault_ca_obj, monkeypatch):

    class MockX509(OpenSSL.crypto.X509):

        def get_notAfter(self):
            return b'20220510141643Z'

    monkeypatch.setattr(OpenSSL.crypto, 'X509', MockX509)
    assert vault_ca_obj._is_certificate_valid('tests/fixtures/acomponent-test.test.org.pem.ok')


def test_is_certificate_valid_false(vault_ca_obj, monkeypatch):

    class MockX509(OpenSSL.crypto.X509):

        def get_notAfter(self):
            return b'20000510141643Z'

    monkeypatch.setattr(OpenSSL.crypto, 'X509', MockX509)

    assert not vault_ca_obj._is_certificate_valid('tests/fixtures/acomponent-test.test.org.pem.ok')


def test_is_certificate_valid_not_exists(vault_ca_obj):
    assert not vault_ca_obj._is_certificate_valid('tests/fixtures/a-non-existent-cert.pem')


def test_is_certificate_valid_false_less_than_24h(vault_ca_obj, monkeypatch):

    class MockX509(OpenSSL.crypto.X509):

        def get_notAfter(self):
            return b'20000510141643Z'

    class MockDatetime(datetime.datetime):

        @classmethod
        def now(cls):
            return datetime.datetime(2000, 5, 9, 15, 16, 43, 100000)

    monkeypatch.setattr(OpenSSL.crypto, 'X509', MockX509)
    monkeypatch.setattr(vault_ca, 'datetime', MockDatetime)

    assert not vault_ca_obj._is_certificate_valid('tests/fixtures/acomponent-test.test.org.pem.ok')


def test_is_certificate_valid_true_more_than_24h(vault_ca_obj, monkeypatch):

    class MockX509(OpenSSL.crypto.X509):

        def get_notAfter(self):
            return b'20000510141643Z'

    class MockDatetime(datetime.datetime):

        @classmethod
        def now(cls):
            return datetime.datetime(2000, 5, 9, 13, 16, 43, 100000)

    monkeypatch.setattr(OpenSSL.crypto, 'X509', MockX509)
    monkeypatch.setattr(vault_ca, 'datetime', MockDatetime)

    assert vault_ca_obj._is_certificate_valid('tests/fixtures/acomponent-test.test.org.pem.ok')


def test_write_files(vault_ca_obj):
    component = "acomponent"
    common_name = "test.test.org"
    cert_data = open('tests/fixtures/acomponent-test.test.org.pem.ok', 'r').read()
    priv_key_data = open('tests/fixtures/acomponent-test.test.org.key', 'r').read()
    ca_data = open('tests/fixtures/acomponent.crt', 'r').read()
    cert_file = os.path.join(vault_ca_obj.output_dir, "{}-{}.pem".format(component, common_name))
    priv_key_file = os.path.join(vault_ca_obj.output_dir, "{}-{}.key".format(component, common_name))
    ca_file = os.path.join(vault_ca_obj.output_dir, "{}.crt".format(component))
    vault_ca_obj._write_files('test.test.org', cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file)
    with open(cert_file, 'r') as pem:
        assert pem.read() == cert_data
    with open(priv_key_file, 'r') as key:
        assert key.read() == priv_key_data


def test_write_files_boostrap_ca(vault_ca_obj_bootstap_ca):
    component = "acomponent"
    common_name = "test.test.org"
    cert_data = open('tests/fixtures/acomponent-test.test.org.pem.ok', 'r').read()
    priv_key_data = open('tests/fixtures/acomponent-test.test.org.key', 'r').read()
    ca_data = open('tests/fixtures/acomponent.crt', 'r').read()
    cert_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}-{}.pem".format(component, common_name))
    priv_key_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}-{}.key".format(component, common_name))
    ca_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}.crt".format(component))
    vault_ca_obj_bootstap_ca.ca_path = vault_ca_obj_bootstap_ca.output_dir
    vault_ca_obj_bootstap_ca._write_files(
        'test.test.org', cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file
    )
    with open(cert_file, 'r') as pem:
        assert pem.read() == cert_data
    with open(priv_key_file, 'r') as key:
        assert key.read() == priv_key_data
    with open(ca_file, 'r') as ca:
        assert ca.read() == ca_data


def test_write_files_boostrap_ca_invalid_cert(vault_ca_obj_bootstap_ca, monkeypatch):

    def mock_is_certificate_valid(certificate_path):
        return True

    monkeypatch.setattr(vault_ca_obj_bootstap_ca, '_is_certificate_valid', mock_is_certificate_valid)

    component = "acomponent"
    common_name = "test.test.org"
    cert_data = open('tests/fixtures/acomponent-test.test.org.pem.ok', 'r').read()
    priv_key_data = open('tests/fixtures/acomponent-test.test.org.key', 'r').read()
    ca_data = open('tests/fixtures/acomponent.crt', 'r').read()
    cert_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}-{}.pem".format(component, common_name))
    priv_key_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}-{}.key".format(component, common_name))
    ca_file = os.path.join(vault_ca_obj_bootstap_ca.output_dir, "{}.crt".format(component))
    vault_ca_obj_bootstap_ca.ca_path = vault_ca_obj_bootstap_ca.output_dir
    vault_ca_obj_bootstap_ca._write_files(
        'test.test.org', cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file
    )
    assert not os.path.isfile(cert_file)
    assert not os.path.isfile(ca_file)


def test_prepare_json_data(vault_ca_obj):
    expected = {'common_name': 'common_name', 'ttl': '8760h'}
    json_data = vault_ca_obj._prepare_json_data('common_name')
    assert json.loads(json_data) == expected


def test_prepare_json_data_alt_names(vault_ca_obj):
    expected = {'common_name': 'common_name', 'ttl': '8760h', 'alt_names': 'altname1,altname2'}
    json_data = vault_ca_obj._prepare_json_data('common_name', alt_names="altname1,altname2")
    assert json.loads(json_data) == expected


def test_prepare_json_data_ip_sans(vault_ca_obj):
    expected = {'common_name': 'common_name', 'ttl': '8760h', 'ip_sans': '10.0.0.1,127.0.0.1'}
    json_data = vault_ca_obj._prepare_json_data('common_name', ip_sans="10.0.0.1,127.0.0.1")
    assert json.loads(json_data) == expected


def test_prepare_json_data_ttl(vault_ca_obj):
    expected = {'common_name': 'common_name', 'ttl': '24h'}
    json_data = vault_ca_obj._prepare_json_data('common_name', ttl="24h")
    assert json.loads(json_data) == expected


def test_analise_response_ok(vault_ca_obj):
    expected = {'akey': 'avalue'}

    class MockRequest:

        @property
        def ok(self):
            return True

        def json(self):
            return expected

    response = vault_ca_obj._analise_response(MockRequest())
    assert response == expected


def test_analise_reponse_ko(vault_ca_obj):

    class MockRequest:

        @property
        def ok(self):
            return False

        @property
        def status_code(self):
            return 404

    with pytest.raises(VaultCAError):
        vault_ca_obj._analise_response(MockRequest())


def test_analise_response_json_error(vault_ca_obj):

    class MockRequest:

        @property
        def ok(self):
            return True

        def json(self):

            class MockJSONDoc:

                def count(self, a, b, c):
                    return 1

                def rfind(self, a, b, c):
                    return 1

            raise json.JSONDecodeError('anerror', MockJSONDoc(), 2)

    with pytest.raises(VaultCAError):
        vault_ca_obj._analise_response(MockRequest())


def test_analise_response_vault_error(vault_ca_obj):
    expected = {'akey': 'avalue', 'errors': ['error1', 'error2']}

    class MockRequest:

        @property
        def ok(self):
            return True

        def json(self):
            return expected

    with pytest.raises(VaultCAError):
        vault_ca_obj._analise_response(MockRequest())


def test_extract_certificates_ok(vault_ca_obj):
    response = {'data': {'certificate': 'cert data', 'private_key': 'key data', 'issuing_ca': 'ca data'}}

    cert_data, priv_key_data, ca_data = vault_ca_obj._extract_certificates(response)
    assert cert_data == "cert data"
    assert priv_key_data == "key data"
    assert ca_data == "ca data"


def test_extract_certificates_no_cert(vault_ca_obj):
    response = {'data': {'private_key': 'key data', 'issuing_ca': 'ca data'}}

    with pytest.raises(VaultCAError):
        vault_ca_obj._extract_certificates(response)


def test_extract_certificates_no_key(vault_ca_obj):
    response = {'data': {'certificate': 'cert data', 'issuing_ca': 'ca data'}}

    with pytest.raises(VaultCAError):
        vault_ca_obj._extract_certificates(response)


def test_extract_certificates_no_ca(vault_ca_obj):
    response = {'data': {'certificate': 'cert data', 'private_key': 'key data'}}

    with pytest.raises(VaultCAError):
        vault_ca_obj._extract_certificates(response)


def test_fetch_200(vault_ca_obj):
    component = "acomponent"
    common_name = "test.test.org"
    cert_file = os.path.join(vault_ca_obj.output_dir, "{}-{}.pem".format(component, common_name))
    priv_key_file = os.path.join(vault_ca_obj.output_dir, "{}-{}.key".format(component, common_name))
    with requests_mock.Mocker() as mock:
        response = {'data': {'certificate': 'cert data', 'private_key': 'key data', 'issuing_ca': 'ca data'}}
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', json=response, status_code=200)
        vault_ca_obj.fetch('test.test.org', ip_sans='10.0.0.1', alt_names='alttest.test.org', ttl='24h')
        assert os.path.isfile(cert_file)
        assert os.path.isfile(priv_key_file)


def test_fetch_404(vault_ca_obj):
    with requests_mock.Mocker() as mock:
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', json={}, status_code=404)
        with pytest.raises(VaultCAError):
            vault_ca_obj.fetch('test.test.org')


def test_fetch_500(vault_ca_obj):
    with requests_mock.Mocker() as mock:
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', json={}, status_code=500)
        with pytest.raises(VaultCAError):
            vault_ca_obj.fetch('test.test.org')


def test_fetch_connect_timeout(vault_ca_obj):
    with requests_mock.Mocker() as mock:
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', exc=requests.exceptions.ConnectTimeout)
        with pytest.raises(VaultCAError):
            vault_ca_obj.fetch('test.test.org')


def test_fetch_connect_error(vault_ca_obj):
    with requests_mock.Mocker() as mock:
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', exc=requests.exceptions.ConnectionError)
        with pytest.raises(VaultCAError):
            vault_ca_obj.fetch('test.test.org')


def test_fetch_valid_cert(vault_ca_obj, monkeypatch):

    def mock_is_certificate_valid(certificate_path):
        return True

    monkeypatch.setattr(vault_ca_obj, '_is_certificate_valid', mock_is_certificate_valid)

    component = "acomponent"
    common_name = "test.test.org"
    cert_file = os.path.join(vault_ca_obj.output_dir, "{}-{}.pem".format(component, common_name))
    ca_file = os.path.join(vault_ca_obj.output_dir, "{}.crt".format(component))
    with requests_mock.Mocker() as mock:
        response = {'data': {'certificate': 'cert data', 'private_key': 'key data', 'issuing_ca': 'ca data'}}
        mock.put('https://vault.test.org:8200/v1/pki/test.org/issue/cert', json=response, status_code=200)
        vault_ca_obj.fetch('test.test.org', ip_sans='10.0.0.1', alt_names='alttest.test.org', ttl='24h')
        assert not os.path.isfile(cert_file)
        assert not os.path.isfile(ca_file)
