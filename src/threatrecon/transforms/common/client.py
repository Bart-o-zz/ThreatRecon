#!/usr/bin/env python

from collections import defaultdict
from hashlib import md5
import requests
import os
import json
from whois import whois
from whois.parser import PywhoisError

__author__ = 'Bart Otten'
__copyright__ = 'Copyright 2014, Threat Recon Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Bart Otten'
__email__ = 'bartotten@gmail.com'
__status__ = 'Development'

dirname = "/tmp/threatrecon"

#Check if dirname exists
if not os.path.isdir(os.path.abspath(dirname)):
    os.makedirs(os.path.abspath(dirname))

#Headers for requests
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:29.0) Gecko/20100101 Firefox/29.0'
}

api_key = 'c1c0732a6477e4ac185b05b049697199'


def string_filter(x):
    x = unicode(x).encode('ascii', 'ignore').encode('utf-8', errors='replace')  # from unicode to str
    return x.translate(None, ''.join(map(chr, range(32))))  # remove the control characters from string


def query_threat_recon(indicator):
    results = defaultdict(list)
    params = {'api_key': api_key, 'indicator': indicator}
    r = requests.post("https://api.threatrecon.co:8080/api/v1/search", data=params, headers=headers)
    data = r.json()
    #Sort RootNodes
    if data['Results']:
        for result in data['Results']:
            key = result['RootNode']
            results[key].append(result)

        #Write RootNode + values to json file
        for RootNode, Value in results.iteritems():
            write_to_file(RootNode, Value)

    return results


def search(value, cache=True):
    if cache:
        read = read_from_file(value)
        if read:
            return True, read
        else:
            return False, query_threat_recon(value)
    else:
        return False, query_threat_recon(value)


def return_set(value):
    if str == type(value):
        a = set()
        a.add(value.lower())
        return a
    if list == type(value):
        return set([a.lower() for a in value])


def lookup_whois(domain):
    error = False
    try:
        w = whois(domain)
    except PywhoisError as error:
        #Return error message
        return error, {}

    return error, {'whois_domains': return_set(w.domain_name) if hasattr(w, 'domain_name') else '',
                   'whois_emails': return_set(w.emails) if hasattr(w, 'emails') else '',
                   'whois_nameservers': return_set(w.name_servers) if hasattr(w, 'emails') else ''}


def read_from_file(domain):
    m = md5()
    m.update('threatrecon_{}'.format(domain))
    sfilename = os.path.join(dirname, "{}.json".format(m.hexdigest()))
    if os.path.isfile(sfilename):
        return json.load(open(sfilename, "rb"))


def write_to_file(domain, data):
    m = md5()
    m.update('threatrecon_{}'.format(domain))
    sfilename = os.path.join(dirname, "{}.json".format(m.hexdigest()))
    if os.path.isfile(sfilename):
        os.remove(sfilename)

    writetofile = open(sfilename, "w+b")
    json.dump(data, fp=writetofile, indent=4, sort_keys=False)

if __name__ == "__main__":
    s = 'serval.essanavy.com'
    t = 'edm.flying100.net'
    #Print RootNodes
    for key, value in search(s, cache=False)[1].iteritems():
        print "{}: Count:{}".format(key, len(value))
