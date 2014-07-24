#!/usr/bin/env python

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Domain, EmailAddress, IPv4Address, NSRecord, Location
from common.entities import ThreatRecon
from common.client import lookup_whois
from canari.maltego.message import UIMessage

__author__ = 'Bart Otten'
__copyright__ = 'Copyright 2014, Threat Recon Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Bart Otten'
__email__ = 'bartotten@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


@configure(
    label='Whois Domain name',
    description='Preforms Whois on Domain name and returns the details',
    uuids=['Socrates.v2.WhoisToThreatRecon'],
    inputs=[('Threat Recon', Domain)],
    debug=False
)
def dotransform(request, response, config):

    error, found = lookup_whois(request.value)

    if not error and found:
        if dict == type(found):
            for result, value in found.iteritems():
                if set == type(value):
                    if "whois_domains" == result:
                        for d in value:
                            e = Domain(d)
                            e.fqdn = d
                            response += e

                    if "whois_emails" == result:
                        for em in value:
                            e = EmailAddress(em)
                            response += e

                    if "whois_nameservers" == result:
                        for w in value:
                            e = NSRecord(w)
                            response += e

    #Display error message in Transform Output
    response += UIMessage(error)

    return response