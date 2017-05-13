import os
import logging
from datetime import datetime, timedelta

from OpenSSL.crypto import load_certificate, FILETYPE_PEM, Error


class VaultCertError(Exception):
    pass


class VaultCert(object):
    ASN1_GENERALIZETIME_FORMAT = "%Y%m%d%H%M%SZ"
    DEFAULT_CERTIFICATE_TTL = '8760h'  # 1 year
    DEFAULT_VALID_INTERVAL_DAYS = 1
    VAULT_ADDRESS = 'https://vault.{}:8002'
    CA_PATH = '/usr/local/share/ca-certificates/{}'

    def __init__(self, kwargs):
        self.component = kwargs['component']
        self.domain = kwargs['domain']
        self.vault_token = kwargs['vault_token']
        self.output_dir = kwargs.get('output_dir') or self.CA_PATH.format(self.domain)
        self.bootstrap_ca = kwargs.get('bootstrap_ca')
        self.ssl_verity = kwargs.get('ssl_verify')
        self.valid_interval = kwargs.get('valid_interval') or self.DEFAULT_VALID_INTERVAL_DAYS
        self.vault_address = kwargs.get('vault_address') or self.VAULT_ADDRESS.format(self.domain)
        self.ca_file = self.CA_PATH.format(self.domain)

    def _make_dirs(self):
        try:
            os.makedirs(self.output_dir)
        except OSError:
            logging.debug('directory %s already exists, skipping creation', self.output_dir)
            pass

    def _parse_asn1_generalizedtime(self, timestamp):
        try:
            datetime.strptime(timestamp, self.ASN1_GENERALIZETIME_FORMAT)
        except ValueError as e:
            logging.error("unable to parse timestamp %s into ASN.1 GENERALIZEDTIME: %s", timestamp, e.msg)
            raise VaultCertError("unable to parse certificate expire date")

    def _load_certificate(self, certificate_path):
        with open(certificate_path, 'r') as pem:
            try:
                certificate = load_certificate(FILETYPE_PEM, pem.read())
            except Error as e:
                logging.error("unable to load certificate %s: %s", certificate_path, e.msg)
                raise VaultCertError("unable to load certificate {}".format(certificate_path))
            else:
                return certificate

    def _is_certificate_valid(self, certificate_path):
        if os.path.exists(certificate_path):
            certificate = self._load_certificate(certificate_path)
            valid_not_after = self._parse_asn1_generalizedtime(certificate.get_notAfter.decode('utf-8'))
            tomorrow = datetime.now() + timedelta(days=self.valid_interval)
            if (tomorrow - valid_not_after) < timedelta(days=self.valid_interval):
                logging.debug(
                    "certificate %s is expiring in less than %d days, renewing required", certificate_path,
                    self.valid_interval
                )
                return False
            else:
                logging.debug(
                    "certificate %s is expiring in more than %d days, skipping renewal", certificate_path,
                    self.valid_interval
                )
                return True
        else:
            logging.debug("certificate %s does not exist on disk, fetching required", certificate_path)
            return False

    def _write_files(self, common_name, cert_data, priv_key_data, ca_data):
        cert_file = os.path.join(self.output_dir, '{}-{}.pem'.format(self.component, common_name))
        priv_key_file = os.path.join(self.output_dir, '{}-{}.key'.format(self.component, common_name))
        with open(cert_file, 'w') as cert, open(priv_key_file, 'w') as priv_key:
            logging.debug("writing certificate for %s on %s", common_name, cert_file)
            cert.write(cert_data)

            logging.debug("writing private key for %s on %s", common_name, priv_key_file)
            priv_key.write(priv_key_data)

            if self.bootstrap_ca:
                with open(self.ca_file, 'w') as ca:
                    logging.debug("writing CA on %s", self.ca_file)
                    ca.write(ca_data)

    def fetch(self, common_name, ip_sans=None, alt_names=None, ttl=None):
        pass
