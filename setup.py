import sys
from distutils.core import setup
from setuptools import find_packages, Command

VERSION = 0.3


class FormatCommand(Command):
    description = "Python auto-formatter"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import yapf
        yapf.main([sys.executable, '--in-place', '--recursive', 'bin', 'vault_ca', 'tests'])


cmdclass = {
    'format': FormatCommand
}

setup(
    name='vault-ca',
    version='{}'.format(VERSION),
    description='Set of utils to create your own CA using hashicorp Vault',
    author='Matteo Bigoi',
    author_email='bigo@crisidev.org',
    url='https://github.com/crisidev/vault-ca',
    license='GPLv3',
    download_url='https://github.com/crisidev/vault-ca/archive/{}.tar.gz'.format(VERSION),
    keywords=['ssl', 'certificate-authority', 'vault'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Unix Shell',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    packages=find_packages(exclude=['docs', 'tests']),
    scripts=['bin/fetch-ssl-cert', 'bin/create-vault-ca'],
    install_requires=['appdirs', 'pyparsing', 'pyopenssl', 'requests'],
    cmdclass=cmdclass,
    setup_requires=['pytest-runner'],
    tests_require=['pytest', 'pytest-cov', 'requests-mock']
)
