from datetime import date, datetime
from OpenSSL import crypto

from django.utils import timezone

from rest_framework import status
from rest_framework import serializers, viewsets
from rest_framework.response import Response

from .models import Certificate, CertificateAuthority
from .managers import CertificateManager, CertificateAuthorityManager
from .utils import serial_from_int

import sys

class CertificateAuthoritySerializer(serializers.ModelSerializer):
    class Meta:
        model = CertificateAuthority

class CertificateAuthorityViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CertificateAuthority.objects.filter(enabled=True)
    serializer_class = CertificateAuthoritySerializer

class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate

class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.filter(revoked=False, expires__gt=timezone.now())
    serializer_class = CertificateSerializer

    def create(self, request, *args, **kwargs):

        # Validate csr
        csrlines = request.data['csr'].splitlines()
        if csrlines[0] != '-----BEGIN CERTIFICATE REQUEST-----' \
                or csrlines[-1] != '-----END CERTIFICATE REQUEST-----':
            return err_response('Enter a valid CSR (in PEM format).')

        # Validate ca
        try:
            ca = CertificateAuthority.objects.filter(enabled=True).get(pk=int(request.data['ca']))
        except Exception as e:
            return err_response(e.args[0])

        # Validate expires - set default of 2 years if not present
        try:
            if request.data['expires'] is not None:
                try:
                    expire_date = datetime.strptime(request.data['expires'], '%Y-%m-%d')
                except:
                    return err_response('Expires date must be in format YYYY-MM-DD.')
        except KeyError:
             d = timezone.now()
             expire_date = d.replace(year = d.year + 2)

        if expire_date < datetime.now():
            return err_response('Expires date cannot be before today.')

        request.data['expires'] = expire_date

        # Iterate over subject hash
        subject = {k: v for k, v in request.data['subject'].items() if v}

        san = ",".join(request.data['subjectAltName'])

        # Set default keyUsage
        request.data['keyUsage'] = [ True, str.encode("digitalSignature,keyAgreement") ]

        # Set default extendedKeyUsage
        request.data['extendedKeyUsage'] = [ False, str.encode("clientAuth,serverAuth") ]

        # Set default "profile"
        request.data['profile'] = "webserver"

        # Create an X509 cert object
        cert = Certificate.objects.init(
            ca=ca,
            csr=request.data['csr'],
            expires=expire_date,
            subject=subject,
            algorithm=request.data['algorithm'],
            subjectAltName=[e.strip() for e in san.split(',')],
            cn_in_san=True,
            keyUsage=request.data['keyUsage'],
            extendedKeyUsage=request.data['extendedKeyUsage'],
        )

        # Add public certificate to request
        request.data['pub'] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")

        # Add serial
        request.data['serial'] = serial_from_int(cert.get_serial_number())

        # Validate and create certificate
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        # Return the certificate
        msg = {}
        msg['pub'] = serializer.data['pub']
        msg['chain'] = ca.pub

        return Response(msg, status=status.HTTP_201_CREATED, headers=headers)

def err_response(err):
    msg = {}
    msg['detail'] = err
    return Response(msg, status.HTTP_400_BAD_REQUEST)
