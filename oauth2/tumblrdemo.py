# adapted from https://requests-oauthlib.readthedocs.org/en/latest/examples/tumblr.html

from pprint import *
import yaml
cred = yaml.load(open("credentials.yml"))["tumblr"]

import logging
logging.basicConfig(level=logging.DEBUG)

# Credentials from the application page
key = cred['id']
secret = cred['secret']

# OAuth URLs given on the application page
request_token_url = 'http://www.tumblr.com/oauth/request_token'
authorization_base_url = 'http://www.tumblr.com/oauth/authorize'
access_token_url = 'http://www.tumblr.com/oauth/access_token'

# Fetch a request token
from requests_oauthlib import OAuth1Session
tumblr = OAuth1Session(key, client_secret=secret, callback_uri='http://www.tumblr.com/dashboard')
tumblr.fetch_request_token(request_token_url)

# Link user to authorization page
authorization_url = tumblr.authorization_url(authorization_base_url)
print('Please go here and authorize,', authorization_url)

# Get the verifier code from the URL
redirect_response = input('Paste the full redirect URL here: ')
tumblr.parse_authorization_response(redirect_response)

# Fetch the access token
tumblr.fetch_access_token(access_token_url)

# Fetch a protected resource
pprint(tumblr.get('http://api.tumblr.com/v2/user/dashboard').json())
