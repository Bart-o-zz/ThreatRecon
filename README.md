ThreatRecon 
===========

Wapacklabs [ThreatRecon](https://threatrecon.co) transforms for Maltego

ThreatRecon example scripts : https://github.com/dechko/threatrecon

# Installation

Clone Repository
`cd ThreatRecon/src`

`canari create-profile threatrecon`

Import Configuration into Maltego

Import Entity into Maltego

Edit your API key in src/threatrecon/transforms/common/client.py line 33

api_key = 'your apikey'


### Required Python modules : 

[Requests](http://docs.python-requests.org/en/latest/) 

[python-whois](https://code.google.com/p/pywhois/) 


# Known bugs

We list all the bugs we know about (plus some things we know we need to add) at the Github issues page.

Error : SSLError: [Errno 1] _ssl.c:504: error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version
Solution : Install requests-sslv3 - https://github.com/joequery/requests-sslv3 

# How you can help

Aside from pull requests, non-developers can open issues on Github. Things we'd really appreciate:

Bug reports, preferably with error logs
Suggestions of additional sources for Maltego transforms
Descriptions of how you use it and ways we can improve it for you
