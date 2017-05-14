import os
import json

import pytest
import OpenSSL
import datetime

import vault_ca
from vault_ca import VaultCA, VaultCAError


@pytest.fixture
def vault_ca_obj(tmpdir):
    kwargs = {
        'component': 'acomponent',
        'domain': 'test.org',
        'vault_token': 'atoken',
        'bootstrap_ca': False,
        'ssl_verity': True,
        'output_dir': str(tmpdir)
    }
    return VaultCA(kwargs)


def test_make_dirs(vault_ca_obj, tmpdir):
    temp_dir = str(tmpdir)
    vault_ca_obj._make_dirs(os.path.join(temp_dir, 'atest'))
    assert os.path.isdir(os.path.join(temp_dir, 'atest'))
    # test it second time to trigger the OSError
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
    cert_data = "cert data"
    priv_key_data = "key data"
    ca_data = "ca data"
    vault_ca_obj._write_files('test.test.org', cert_data, priv_key_data, ca_data)
    with open(os.path.join(vault_ca_obj.output_dir, "{}-{}.pem".format(component, common_name)), 'r') as pem:
        assert pem.read() == cert_data
    with open(os.path.join(vault_ca_obj.output_dir, "{}-{}.key".format(component, common_name)), 'r') as key:
        assert key.read() == priv_key_data
    vault_ca_obj.bootstrap_ca = True
    vault_ca_obj.ca_path = vault_ca_obj.output_dir
    vault_ca_obj._write_files('test.test.org', cert_data, priv_key_data, ca_data)
    with open(os.path.join(vault_ca_obj.output_dir, "{}.crt".format(component)), 'r') as ca:
        assert ca.read() == ca_data


def test_prepare_json_data(vault_ca_obj):
    expected = '{"common_name": "common_name", "ttl": "8760h"}'
    json_data = vault_ca_obj._prepare_json_data('common_name')
    assert json_data == expected


def test_prepare_json_data_alt_names(vault_ca_obj):
    expected = '{"common_name": "common_name", "ttl": "8760h", "alt_names": "altname1,altname2"}'
    json_data = vault_ca_obj._prepare_json_data('common_name', alt_names="altname1,altname2")
    assert json_data == expected


def test_prepare_json_data_ip_sans(vault_ca_obj):
    expected = '{"common_name": "common_name", "ttl": "8760h", "ip_sans": "10.0.0.1,127.0.0.1"}'
    json_data = vault_ca_obj._prepare_json_data('common_name', ip_sans="10.0.0.1,127.0.0.1")
    assert json_data == expected


def test_prepare_json_data_ttl(vault_ca_obj):
    expected = '{"common_name": "common_name", "ttl": "24h"}'
    json_data = vault_ca_obj._prepare_json_data('common_name', ttl="24h")
    assert json_data == expected


def test_analise_request_ok(vault_ca_obj):
    expected = {'akey': 'avalue'}

    class MockRequest:

        @property
        def ok(self):
            return True

        def json(self):
            return expected

    response = vault_ca_obj._analise_request(MockRequest())
    assert response == expected


def test_analise_request_ko(vault_ca_obj):

    class MockRequest:

        @property
        def ok(self):
            return False

        @property
        def status_code(self):
            return 404

    with pytest.raises(VaultCAError):
        vault_ca_obj._analise_request(MockRequest())


def test_analise_request_json_error(vault_ca_obj):

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
        vault_ca_obj._analise_request(MockRequest())


def test_analise_request_vault_error(vault_ca_obj):
    expected = {'akey': 'avalue', 'errors': ['error1', 'error2']}

    class MockRequest:

        @property
        def ok(self):
            return True

        def json(self):
            return expected

    with pytest.raises(VaultCAError):
        vault_ca_obj._analise_request(MockRequest())


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
