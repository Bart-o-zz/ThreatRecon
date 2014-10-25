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

## Some Basics ##

- it never hurts to have a working and updated Python 

  On Kali start with: sudo apt-get update && sudo apt-get upgrade
  install python-setuptools and python pip
  ok - once you have done that update both
  pip install pip --upgrade
  pip install setuptools --upgrade
  pip install requests
  pip install python-whois



### Required Python modules : 

[Requests](http://docs.python-requests.org/en/latest/) 

[python-whois](https://code.google.com/p/pywhois/) 


# Known bugs


# How you can help

Aside from pull requests, non-developers can open issues on Github. Things we'd really appreciate:

Bug reports, preferably with error logs
Suggestions of additional sources for Maltego transforms
Descriptions of how you use it and ways we can improve it for you
