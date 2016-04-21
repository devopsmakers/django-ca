# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-04-21 22:15
from __future__ import unicode_literals

from OpenSSL import crypto

from django.db import migrations

from ..utils import parse_date

def set_ca_props(apps, schema_editor):
    CA = apps.get_model('django_ca', 'CertificateAuthority')
    for ca in CA.objects.all():
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ca.pub)
        ca.expires = parse_date(x509.get_notAfter().decode('utf-8'))
        ca.cn = dict(x509.get_subject().get_components()).get(b'CN').decode('utf-8')
        ca.save()


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0011_auto_20160421_2200'),
    ]

    operations = [
        migrations.RunPython(set_ca_props),
    ]
