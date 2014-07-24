#!/usr/bin/env python

from canari.maltego.utils import debug
from canari.framework import configure
from canari.maltego.entities import Domain, IPv4Address, EmailAddress, Netblock, NSRecord, PhoneNumber, Location, Phrase
from common.entities import ThreatRecon, NetNameThreatRecon
from common.client import search, string_filter
from canari.maltego.message import Field, Label

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
    label='Get Indicators from RootNode',
    description='Returns Indicators From RootNode Threat Recon',
    uuids=['Socrates.v2.RootNodeToIndicator'],
    inputs=[('Threat Recon', ThreatRecon)],
    debug=False
)
def dotransform(request, response, config):

    tr_details = ['Reference', 'Source', 'KillChain', 'Firstseen', 'Lastseen', 'Attribution',
                  'ProcessType', 'Rrname', 'Rdata', 'Country', 'Tags', 'Comment',
                  'RootNode', 'Confidence']

    #Default link color is black
    linkcolor = "0x000000"

    cache, found = search(request.value)

    if found:
        debug(found)
        for indicator in found:
            debug(indicator)
            e = ''
            indtype = indicator['Type'].lower().strip()

            if "whois email" == indtype:
                e = EmailAddress(indicator['Indicator'])
                #response += e

            if "name server" == indtype:
                e = NSRecord(indicator['Indicator'])
                #response += e

            if "domain" == indtype:
                e = Domain(indicator['Indicator'])
                e.fqdn = indicator['Indicator']
                #response += e
            #IF Type is not domain, check if Rrname is not empty
            elif indicator['Rrname'] and indicator['Rrname'] != 'NA':
                d = Domain("*{}".format(indicator['Rrname']))
                d.fqdn = "*{}".format(indicator['Rrname'])
                response += d

            if "ip" == indtype:
                e = IPv4Address(indicator['Indicator'])
                #response += e
            #IF Type is not IP, check if Rdata is not empty
            elif indicator['Rdata']:
                i = IPv4Address(indicator['Rdata'])
                response += i

            if "phone or fax no." == indtype:
                e = PhoneNumber(indicator['Indicator'])
                #response += e

            if "whois address component" == indtype:
                e = Phrase(indicator['Indicator'])
                #response += e

            if "email" == indtype:
                e = EmailAddress(indicator['Indicator'])
                #response += e

            if "netname" == indtype:
                e = NetNameThreatRecon(indicator['Indicator'])
                #response += e

            if "cidr" == indtype:
                e = IPv4Address(indicator['Indicator'])
                #response += e

            if "netrange" == indtype:
                e = Netblock(indicator['Indicator'])
                #response += e

            if indicator['Country']:
                l = Location(indicator['Country'])
                response += l


            #Add Comments and details to own Entity
            entity = e #request.entity

            #Set comments
            if indicator['Comment']:
                entity.notes = string_filter(indicator['Comment'])

                #Set Details
            for detail in tr_details:
                if detail in indicator:
                    if indicator[detail]:
                        entity += Label(name=detail, value=string_filter(indicator[detail]))

            #Set link color
            if "Confidence" in indicator:
                if indicator['Confidence'] >= 70:
                    linkcolor = "0xff0000"

            entity.linkcolor = linkcolor

            response += entity

    return response