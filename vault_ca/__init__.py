import os
import json
import logging
from datetime import datetime, timedelta

import requests
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, Error

VERSION = 0.5

# fix incompatibility between python 3.4 and 3.5+ json implementation
if not hasattr(json, 'JSONDecodeError'):  # pragma: nocover
    json.JSONDecodeError = ValueError


class VaultCAError(Exception):
    """
    VaultCA custom exception
    """
    pass


class VaultCA(object):
    """
    Object to handle fetching ot certificate/key pairs and CA.
    """
    ASN1_GENERALIZEDTIME_FORMAT = "%Y%m%d%H%M%SZ"
    DEFAULT_CERTIFICATE_TTL = '8760h'  # 1 year
    DEFAULT_VALID_INTERVAL_DAYS = 1
    VAULT_ADDRESS = "https://vault.{}:8200"
    VAULT_PATH = "v1/pki/{}/issue/cert"
    CA_PATH = "/usr/local/share/ca-certificates/{}"
    MANDATORY_ARGS = ('component', 'domain', 'vault_token')

    def __init__(self, kwargs):
        """
        Initialize object and its attributes.

        :param kwargs: arguments dictionary
        :type kwargs: dict
        """
        self._validate_args(kwargs)
        self._manage_args(kwargs)

    def _manage_args(self, kwargs):
        """
        Setup object attributes for later usage.

        :param kwargs: arguments dictionary
        :type kwargs: dict
        """

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
        """
        Validate that mandatory arguments are present.

        :param kwargs: arguments dictionary
        :type kwargs: dict

        :raises VaultCAError: if there are missing mandatory arguments
        """

        missing_args = []
        for arg in self.MANDATORY_ARGS:
            if arg not in kwargs.keys():
                logging.error("missing mandatory init argument `%s`", arg)
                missing_args.append(arg)
        if missing_args:
            raise VaultCAError("missing mandatory init arguments `%s`", ', '.join(missing_args))

    def _make_dirs(self, directory):
        """
        Create directory if not present.

        :param directory: directory to create
        :type directory: str
        """
        if not os.path.exists(directory):
            os.makedirs(directory)

    def _parse_asn1_generalizedtime(self, timestamp):
        """
        Parse a timestamp coming from PyOpenSSL X509 object into datetime.

        :param timestamp: ASN.1 GENERALIZEDTIME timestamp
        :type timestamp: str

        :return: parsed timestamp
        :rtype: datetime.datetime

        :raises VaultCAError: if the format is not parsable
        """
        try:
            return datetime.strptime(timestamp, self.ASN1_GENERALIZEDTIME_FORMAT)
        except ValueError as e:
            logging.error("unable to parse timestamp `%s` into ASN.1 GENERALIZEDTIME: %s", timestamp, e)
            raise VaultCAError("unable to parse certificate expire date")

    def _load_certificate(self, certificate_path):
        """
        Load certificate or CA from disk.

        :param certificate_path: certificate path on disk
        :type certificate_path: str

        :return: the loaded certificate
        :rtype: OpenSSL.crypto.X509

        :raises VaultCAError: if the certificate is not loadable
        """
        with open(certificate_path, 'r') as pem:
            try:
                certificate = load_certificate(FILETYPE_PEM, pem.read())
            except Error as e:
                logging.error("unable to load certificate `%s`: %s", certificate_path, e)
                raise VaultCAError("unable to load certificate `{}`".format(certificate_path))
            else:
                return certificate

    def _is_certificate_valid(self, certificate_path):
        """
        Check if a certificate or CA is still valid.

        The check is done comparing the notValidAfter date of the certificate with a day in the future,
        based on `self.valid_interval` parameters.

        If the certificate is due to expire less than `self.valid_interval` days, it is marked it to be renewed.

        :param certificate_path: certificate path on disk
        :type certificate_path: str

        :return: certificate is valid or not
        :rtype: bool
        """
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
        """
        Store certificate, private key and CA on disk, if the ones already found on disk are not valid anymore.

        :param common_name: common name for the certificate / key pair
        :type common_name: str
        :param cert_data: certificate data
        :type cert_data: str
        :param cert_file: certificate path on disk
        :type cert_file: str
        :param priv_key_data: private key data
        :type priv_key_data: str
        :param priv_key_file: private key path on disk
        :type priv_key_file: str
        :param ca_data: CA data
        :type ca_data: str
        :param ca_file: CA path on disk
        :type ca_file: str
        """
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
        """
        Prepare the json payload to be sent to Vault with the new certificate request.

        :param common_name: common name for the certificate / key pair
        :type common_name: str
        :param ip_sans: list of IP for the current certificate, comma separated
        :type ip_sans: str
        :param alt_names: list of alternative names for the current certificate, comma separated
        :type alt_names: str
        :param ttl: TTL for the certificate / key pair
        :type ttl: str

        :return: json encoded payload
        :rtype: str
        """
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

    def _analise_response(self, response):
        """
        Analise response from Vault to find errors and extract the json response payload.

        :type reponse: vault HTTP response
        :type response: requests.models.Response

        :return: json response payload
        :rtype: dict

        :raises VaultCAError: if HTTP code is not ok or there are errors
        """
        if response.ok:
            try:
                payload = response.json()
            except json.JSONDecodeError as e:
                logging.error("error decoding json response: %s", e)
                raise VaultCAError("error decoding json response")
            else:
                errors = payload.get('errors')
                if errors:
                    logging.error("vault returned errors generating cert / key pair: %s", " ".join(errors))
                    raise VaultCAError("vault returned errors generating cert / key pair")
                else:
                    return payload
        else:
            logging.error("vault returned HTTP code `%s`", response.status_code)
            raise VaultCAError("vault returned HTTP error")

    def _extract_certificates(self, payload):
        """
        Extract certificate, private key and CA from Vault response.

        :param payload: json response payload
        :type payload: dict
        :return: certificate, private key and CA
        :rtype: tuple

        :raises VaultCAError: if certificate or private key or CA are missing
        """

        cert_data = payload.get('data', {}).get('certificate')
        if not cert_data:
            logging.error("vault payload is missing certificate data")
            raise VaultCAError("vault payload is missing certificate data")

        priv_key_data = payload.get('data', {}).get('private_key')
        if not priv_key_data:
            logging.error("vault payload is missing private key data")
            raise VaultCAError("vault payload is missing private key data")

        ca_data = payload.get('data', {}).get('issuing_ca')
        if not ca_data:
            logging.error("vault payload is missing CA data")
            raise VaultCAError("vault payload is missing CA data")

        return cert_data, priv_key_data, ca_data

    def fetch(self, common_name, ip_sans=None, alt_names=None, ttl=None):
        """
        Fetch new certificate / key pair from Vault.

        If attribute `self.bootstrap_ca` is set to True, also the CA is fetched.

        Fetched object are written on disk.

        :param common_name: common name for the certificate / key pair
        :type common_name: str
        :param ip_sans: list of IP for the current certificate, comma separated
        :type ip_sans: str
        :param alt_names: list of alternative names for the current certificate, comma separated
        :type alt_names: str
        :param ttl: TTL for the certificate / key pair

        :raises VaultCAError: if the request return errors
        """
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
                response = requests.put(url, data=data, headers=headers, verify=self.ssl_verify)
            except requests.exceptions.RequestException as e:
                logging.error("exception connecting to vault endpoint: %s", e)
                raise VaultCAError("exception connecting to vault endpoint")
            else:
                payload = self._analise_response(response)

            cert_data, priv_key_data, ca_data = self._extract_certificates(payload)
            self._write_files(common_name, cert_data, cert_file, priv_key_data, priv_key_file, ca_data, ca_file)
