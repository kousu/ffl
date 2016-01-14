#!/usr/bin/python3 -i
"""

 `sudo pip{2,3} install python-openid`
"""

from __future__ import print_function
#


try:
	from urllib.parse import * #py3
except ImportError:
	from urlparse import * #py2

# this is a fork and has to be installed from PIP! it's in a sad state!!
# 
import openid.consumer.consumer 

session = '0123456789124453'
client = openid.consumer.consumer.Consumer({"id": session}, None) #le sigh

id = input("Enter your OpenID URL: ")
req = client.begin(id)

# here you  can req.add_extension() with various extra features
# the most obvious is the "account details" feature
# other good ones (which should just be on all the time) are immediate mode, PAPE (the anti phishing mode; not that it's a guarantee)
#req.

realm = "http://localhost.localdomain:8001/" #XXX this should really be attached to the consumer already, shouln'd it? fuck this library
return_to = "http://localhost.localdomain:8001/process"
if req.shouldSendRedirect():
	print("using GET")
else:
	print("Using POST (not really)")

# this always uses the redirectURL, a very similar flow to OAuth
auth_url = req.redirectURL(realm, return_to)
print("Go to", auth_url)
resp = input("Paste in where it redirects you to: ")

resp = parse_qs(urlsplit(resp).query)
resp = {k: v[0] for k,v in resp.items()} #strip the list (multi-valued items can fuck off good and well)
verify = client.complete(resp, return_to) #argh, why?

# BEWARE: the return_to URL *must* be HTTPS, because it sends a 
# see https://en.wikipedia.org/wiki/OpenID#Authentication_Hijacking_in_Unsecured_Connection

print(verify) #DEBUG
if isinstance(verify, openid.consumer.consumer.SuccessResponse):
	print("Logged in as", verify.identity_url)
