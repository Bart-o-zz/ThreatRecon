#!/usr/bin/env python

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Domain, NSRecord, IPv4Address, EmailAddress, Netblock, PhoneNumber, Phrase
from common.entities import ThreatRecon, NetNameThreatRecon
from common.client import search, string_filter
from canari.maltego.message import Field, Label, UIMessage

from collections import defaultdict

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
    label='Email Address to Threat Recon',
    description='Returns RootNodes from Threat Recon',
    uuids=['Socrates.v2.EmailAddressToThreatRecon'],
    inputs=[('Threat Recon', EmailAddress)],
    debug=False
)
def dotransform(request, response, config):

    tr_details = ['Reference', 'Source', 'KillChain', 'Firstseen', 'Lastseen', 'Attribution',
                  'ProcessType', 'Rrname', 'Rdata', 'Country', 'Tags', 'Comment',
                  'RootNode', 'Confidence']

    #Disable cache to get actual data from Threat Recon
    cache, found = search(request.value, cache=False)

    #Default linkcolor
    linkcolor = "0x000000"

    if found:
        if defaultdict == type(found):
            for rootnode, value in found.iteritems():
                #If the RootNode is empty, display attributes
                if len(rootnode) == 0:
                    for indicator in value:
                        #debug(indicator)
                        e = ''
                        indtype = indicator['Type'].lower().strip()

                        if "whois email" == indtype:
                            e = EmailAddress(indicator['Indicator'])

                        if "name server" == indtype:
                            e = NSRecord(indicator['Indicator'])

                        if "domain" == indtype:
                            e = Domain(indicator['Indicator'])
                            e.fqdn = indicator['Indicator']

                        if "ip" == indtype:
                            e = IPv4Address(indicator['Indicator'])

                        if "phone or fax no." == indtype:
                            e = PhoneNumber(indicator['Indicator'])

                        if "whois address component" == indtype:
                            e = Phrase(indicator['Indicator'])

                        if "email" == indtype:
                            e = EmailAddress(indicator['Indicator'])

                        if "netname" == indtype:
                            e = NetNameThreatRecon(indicator['Indicator'])

                        if "cidr" == indtype:
                            e = IPv4Address(indicator['Indicator'])

                        if "netrange" == indtype:
                            e = Netblock(indicator['Indicator'])

                        if e:
                            #Set linkcolor
                            e.linkcolor = linkcolor

                            #Set comments
                            if indicator['Comment']:
                                e.notes = string_filter(indicator['Comment'])

                            #Set Details
                            for detail in tr_details:
                                if detail in indicator:
                                    if indicator[detail]:
                                        e += Label(name=detail, value=string_filter(indicator[detail]))

                            response += e
                else:
                    #Display the RootNodes
                    e = ThreatRecon(rootnode)
                    response += e
    return response