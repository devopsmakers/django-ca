from datetime import date, datetime
from OpenSSL import crypto

from rest_framework import status
from rest_framework import serializers, viewsets
from rest_framework.response import Response

from .models import Certificate, CertificateAuthority
from .managers import CertificateManager, CertificateAuthorityManager
from .utils import serial_from_int

class CertificateAuthoritySerializer(serializers.ModelSerializer):
    class Meta:
        model = CertificateAuthority

class CertificateAuthorityViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CertificateAuthority.objects.all()
    serializer_class = CertificateAuthoritySerializer

class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate

class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerializer

    def create(self, request, *args, **kwargs):

        request.data['expires'] = datetime.strptime(request.data['expires'], '%Y-%m-%d')

        san, cn_in_san = request.data['subjectAltName']
        subject = {k: v for k, v in request.data['subject'].items() if v}
        expires = datetime.combine(request.data['expires'], datetime.min.time())
        ca = CertificateAuthority.objects.get(pk=int(request.data['ca']))
        request.data['keyUsage'][1] = str.encode(request.data['keyUsage'][1])
        request.data['extendedKeyUsage'][1] = str.encode(request.data['extendedKeyUsage'][1])

        cert = Certificate.objects.init(
            ca=ca,
            csr=request.data['csr'],
            expires=expires,
            subject=subject,
            algorithm=request.data['algorithm'],
            subjectAltName=[e.strip() for e in san.split(',')],
            cn_in_san=cn_in_san,
            keyUsage=request.data['keyUsage'],
            extendedKeyUsage=request.data['extendedKeyUsage'],
        )
        request.data['pub'] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
        request.data['serial'] = serial_from_int(cert.get_serial_number())

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
