import os
import json
import logging
from datetime import datetime, timedelta

import requests
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, Error

VERSION = 0.2

# fix incompatibility between python 3.4 and 3.5+ json implementation
if not hasattr(json, 'JSONDecodeError'):  # pragma: nocover
    json.JSONDecodeError = ValueError


class VaultCAError(Exception):
    pass


class VaultCA(object):
    ASN1_GENERALIZETIME_FORMAT = "%Y%m%d%H%M%SZ"
    DEFAULT_CERTIFICATE_TTL = '8760h'  # 1 year
    DEFAULT_VALID_INTERVAL_DAYS = 1
    VAULT_ADDRESS = "https://vault.{}:8200"
    VAULT_PATH = "v1/pki/{}/issue/cert"
    CA_PATH = "/usr/local/share/ca-certificates/{}"
    MANDATORY_ARGS = ('component', 'domain', 'vault_token')

    def __init__(self, kwargs):
        self._validate_args(kwargs)
        self._manage_args(kwargs)

    def _manage_args(self, kwargs):
        self.component = kwargs['component']
        self.domain = kwargs['domain']
        self.vault_token = kwargs['vault_token']
        self.output_dir = kwargs.get('output_dir') or self.CA_PATH.format(self.domain)
        self.bootstrap_ca = kwargs.get('bootstrap_ca')
        if self.bootstrap_ca and kwargs.get('ssl_verify') is not True:
            self.ssl_verify = False
        else:
            self.ssl_verify = kwargs.get('ssl_verify')
        self.valid_interval = kwargs.get('valid_interval') or self.DEFAULT_VALID_INTERVAL_DAYS
        self.vault_address = kwargs.get('vault_address') or self.VAULT_ADDRESS.format(self.domain)
        self.ca_path = kwargs.get('ca_path') or self.CA_PATH.format(self.domain)
        logging.debug('vault address is `%s`', self.vault_address)

    def _validate_args(self, kwargs):
        missing_args = []
        for arg in self.MANDATORY_ARGS:
            if arg not in kwargs.keys():
                logging.error("missing mandatory init argument `%s`", arg)
                missing_args.append(arg)
        if missing_args:
            raise VaultCAError("missing mandatory init arguments `%s`", ', '.join(missing_args))

    def _make_dirs(self, directory):
        try:
            os.makedirs(directory)
        except OSError:
            logging.debug("directory `%s` already exists, skipping creation", self.output_dir)
            pass

    def _parse_asn1_generalizedtime(self, timestamp):
        try:
            return datetime.strptime(timestamp, self.ASN1_GENERALIZETIME_FORMAT)
        except ValueError as e:
            logging.error("unable to parse timestamp `%s` into ASN.1 GENERALIZEDTIME: %s", timestamp, e)
            raise VaultCAError("unable to parse certificate expire date")

    def _load_certificate(self, certificate_path):
        with open(certificate_path, 'r') as pem:
            try:
                certificate = load_certificate(FILETYPE_PEM, pem.read())
            except Error as e:
                logging.error("unable to load certificate `%s`: %s", certificate_path, e)
                raise VaultCAError("unable to load certificate `{}`".format(certificate_path))
            else:
                return certificate

    def _is_certificate_valid(self, certificate_path):
        if os.path.exists(certificate_path):
            certificate = self._load_certificate(certificate_path)
            valid_not_after = self._parse_asn1_generalizedtime(certificate.get_notAfter().decode('utf-8'))
            if (valid_not_after - datetime.now()) < timedelta(days=self.valid_interval):
                logging.debug(
                    "certificate `%s` is expiring in less than %d days, renewing required", certificate_path,
                    self.valid_interval
                )
                return False
            else:
                logging.debug(
                    "certificate `%s` is expiring in more than %d days, skipping renewal", certificate_path,
                    self.valid_interval
                )
                return True
        else:
            logging.debug("certificate `%s` does not exist on disk, fetching required", certificate_path)
            return False

    def _write_files(self, common_name, cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file):
        if not self._is_certificate_valid(cert_file):
            with open(cert_file, 'w') as cert, open(priv_key_file, 'w') as priv_key:
                logging.debug("writing certificate for %s on %s", common_name, cert_file)
                cert.write(cert_data)

                logging.debug("writing private key for %s on %s", common_name, priv_key_file)
                priv_key.write(priv_key_data)

        if self.bootstrap_ca and not self._is_certificate_valid(ca_file):
            with open(ca_file, 'w') as ca:
                logging.debug("writing CA on %s", ca_file)
                ca.write(ca_data)

    def _prepare_json_data(self, common_name, ip_sans=None, alt_names=None, ttl=None):
        if not ttl:
            ttl = self.DEFAULT_CERTIFICATE_TTL

        data = {'common_name': common_name, 'ttl': ttl}

        if ip_sans:
            data['ip_sans'] = ip_sans

        if alt_names:
            data['alt_names'] = alt_names

        logging.debug(
            "requesting new cert / key part for CA domain: `%s`, component: `%s`, common_name: `%s`, ip_sans: `%s`, "
            "alt_names: `%s`, ttl: `%s`", self.domain, self.component, common_name, ip_sans, alt_names, ttl
        )

        return json.dumps(data)

    def _analise_request(self, request):
        if request.ok:
            try:
                response = request.json()
            except json.JSONDecodeError as e:
                logging.error("error decoding json response: %s", e)
                raise VaultCAError("error decoding json response")
            else:
                errors = response.get('errors')
                if errors:
                    logging.error("vault returned errors generating cert / key pair: %s", " ".join(errors))
                    raise VaultCAError("vault returned errors generating cert / key pair")
                else:
                    return response
        else:
            logging.error("vault returned HTTP code `%s`", request.status_code)
            raise VaultCAError("vault returned HTTP error")

    def _extract_certificates(self, response):
        cert_data = response.get('data', {}).get('certificate')
        if not cert_data:
            logging.error("vault response is missing certificate data")
            raise VaultCAError("vault response is missing certificate data")

        priv_key_data = response.get('data', {}).get('private_key')
        if not priv_key_data:
            logging.error("vault response is missing private key data")
            raise VaultCAError("vault response is missing private key data")

        ca_data = response.get('data', {}).get('issuing_ca')
        if not ca_data:
            logging.error("vault response is missing CA data")
            raise VaultCAError("vault response is missing CA data")

        return cert_data, priv_key_data, ca_data

    def fetch(self, common_name, ip_sans=None, alt_names=None, ttl=None):
        self._make_dirs(self.output_dir)
        self._make_dirs(self.ca_path)

        cert_file = os.path.join(self.output_dir, '{}-{}.pem'.format(self.component, common_name))
        priv_key_file = os.path.join(self.output_dir, '{}-{}.key'.format(self.component, common_name))
        ca_file = os.path.join(self.ca_path, "{}.crt".format(self.component))

        if not self._is_certificate_valid(cert_file) or not self._is_certificate_valid(ca_file):
            url = "{}/{}".format(self.vault_address, self.VAULT_PATH.format(self.domain))
            logging.debug("request url is `%s`", url)

            headers = {'X-Vault-Token': self.vault_token}
            data = self._prepare_json_data(common_name, ip_sans=ip_sans, alt_names=alt_names, ttl=ttl)

            try:
                request = requests.put(url, data=data, headers=headers, verify=self.ssl_verify)
            except requests.exceptions.RequestException as e:
                logging.error("exception connecting to vault endpoint: %s", e)
                raise VaultCAError("exception connecting to vault endpoint")
            else:
                response = self._analise_request(request)

            cert_data, priv_key_data, ca_data = self._extract_certificates(response)
            self._write_files(common_name, cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file)
