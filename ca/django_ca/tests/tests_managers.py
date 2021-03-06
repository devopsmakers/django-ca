# -*- coding: utf-8 -*-
#
# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

from ..models import Certificate
from ..models import CertificateAuthority
from ..utils import get_cert_profile_kwargs
from .base import DjangoCAWithCSRTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class GetCertTestCase(DjangoCAWithCSRTestCase):
    def assertExtensions(self, cert, expected):
        expected[b'basicConstraints'] = 'CA:FALSE'
        expected[b'authorityKeyIdentifier'] = self.ca.authorityKeyIdentifier()

        if self.ca.issuer_alt_name:
            expected[b'issuerAltName'] = 'URI:%s' % self.ca.issuer_alt_name
        else:
            expected[b'issuerAltName'] = self.ca.subjectAltName()

        # TODO: Does not account for multiple CRLs yet
        if self.ca.crl_url:
            expected[b'crlDistributionPoints'] = '\nFull Name:\n  URI:%s\n' % self.ca.crl_url

        auth_info_access = ''
        if self.ca.ocsp_url:
            auth_info_access += 'OCSP - URI:%s\n' % self.ca.ocsp_url
        if self.ca.issuer_url:
            auth_info_access += 'CA Issuers - URI:%s\n' % self.ca.issuer_url
        if auth_info_access:
            expected[b'authorityInfoAccess'] = auth_info_access

        exts = [cert.get_extension(i) for i in range(0, cert.get_extension_count())]
        exts = {ext.get_short_name(): str(ext) for ext in exts}

        # TODO: Can't find out how to calculate this, so we just verify presence and length
        skid = exts.pop(b'subjectKeyIdentifier')
        self.assertEqual(len(skid), 59)

        self.assertEqual(exts, expected)

    def test_basic(self):
        kwargs = get_cert_profile_kwargs()

        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(cert.get_signature_algorithm(), b'sha256WithRSAEncryption')

        # verify subject
        expected_subject = kwargs['subject']
        expected_subject['CN'] = 'example.com'
        self.assertSubject(cert, expected_subject)

        self.assertEqual(cert.get_signature_algorithm(), b'sha256WithRSAEncryption')

        # verify extensions
        extensions = {
            b'extendedKeyUsage': 'TLS Web Server Authentication',
            b'keyUsage': 'Digital Signature, Key Encipherment, Key Agreement',
            b'subjectAltName': 'DNS:example.com',
        }

        self.assertExtensions(cert, extensions)

    def test_no_subject(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertSubject(cert, {'CN': 'example.com'})

        # verify extensions
        self.assertExtensions(cert, {
            b'extendedKeyUsage': 'TLS Web Server Authentication',
            b'keyUsage': 'Digital Signature, Key Encipherment, Key Agreement',
            b'subjectAltName': 'DNS:example.com',
        })

    def test_no_names(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']

        with self.assertRaises(ValueError):
            Certificate.objects.init(
                self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
                subjectAltName=[], **kwargs)
        with self.assertRaises(ValueError):
            Certificate.objects.init(
                self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
                subjectAltName=None, **kwargs)

    def test_cn_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:cn.example.com', 'DNS:example.com'], self.get_alt_names(cert))

        # try the same with no SAN at all
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256', **kwargs)
        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:cn.example.com'], self.get_alt_names(cert))

    def test_cn_not_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:example.com'], self.get_alt_names(cert))

    def test_no_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256', **kwargs)
        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertNotIn('subjectAltName', self.get_extensions(cert))

    def test_no_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['keyUsage']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('keyUsage', self.get_extensions(cert))

    def test_no_ext_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['extendedKeyUsage']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('extendedKeyUsage', self.get_extensions(cert))

    def test_crl(self):
        # get from the db to make sure that values do not influence other testcases
        ca = CertificateAuthority.objects.first()
        ca.crl_url = 'http://crl.example.com'

        kwargs = get_cert_profile_kwargs()
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)
        self.assertEqual(self.get_extensions(cert)['crlDistributionPoints'],
                         '\nFull Name:\n  URI:%s\n' % ca .crl_url)

        # test multiple URLs
        ca.crl_url = 'http://crl.example.com\nhttp://crl.example.org'
        kwargs = get_cert_profile_kwargs()
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        expected = '\nFull Name:\n  URI:%s\n\nFull Name:\n  URI:%s\n' % tuple(
            ca.crl_url.splitlines())
        self.assertEqual(self.get_extensions(cert)['crlDistributionPoints'], expected)

    def test_issuer_alt_name(self):
        ca = CertificateAuthority.objects.first()
        ca.issuer_alt_name = 'http://ian.example.com'

        kwargs = get_cert_profile_kwargs()
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['issuerAltName'], 'URI:%s' % ca.issuer_alt_name)

    def test_auth_info_access(self):
        ca = CertificateAuthority.objects.first()
        kwargs = get_cert_profile_kwargs()

        # test only with ocsp url
        ca.ocsp_url = 'http://ocsp.ca.example.com'
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'OCSP - URI:%s\n' % ca.ocsp_url)

        # test with both ocsp_url and issuer_url
        ca.issuer_url = 'http://ca.example.com/ca.crt'
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'OCSP - URI:%s\nCA Issuers - URI:%s\n' % (ca.ocsp_url, ca.issuer_url))

        # test only with issuer url
        ca.ocsp_url = None
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm='sha256',
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'CA Issuers - URI:%s\n' % ca.issuer_url)
