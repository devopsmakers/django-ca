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

from django.core.management.base import CommandError

from OpenSSL import crypto

from ..base import BaseCommand


class Command(BaseCommand):
    help = "Dump a certificate authority to a file."
    binary_output = True

    def add_arguments(self, parser):
        super(BaseCommand, self).add_arguments(parser)
        self.add_format(parser)
        self.add_ca(parser, arg='ca', allow_disabled=True)
        parser.add_argument('path', nargs='?', default='-',
                            help='Path where to dump the certificate. Use "-" for stdout.')

    def handle(self, ca, path, **options):
        data = crypto.dump_certificate(options['format'], ca.x509)
        if path == '-':
            self.stdout.write(data, ending=b'')
        else:
            try:
                # mistakenly reported by coverage 4.0.3 as missed branch, fixed in 4.1:
                # https://bitbucket.org/ned/coveragepy/issues/146/context-managers-confuse-branch-coverage#comment-24552176
                with open(path, 'wb') as stream:  # pragma: no branch
                    stream.write(data)
            except FileNotFoundError as e:
                raise CommandError(e)