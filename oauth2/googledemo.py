
#bewware, requests-oauthlib 2.9.1 and below has this line in fetch_token():
#  >         auth = auth or requests.auth.HTTPBasicAuth(username, password)
# most providers ignore the Authorization: header when not asked for, but Google is picky and if this header is there it will 400 the request with no explanation
# Newere requests-oauthlib ran into this I guess and now it says
#  >        if (not auth) and username:
#  >          if password is None:
#  >            raise ValueError('Username was supplied, but not password.')
#  >          auth = requests.auth.HTTPBasicAuth(username, password)
# which is a lot more reasonable

import logging
logging.basicConfig(level=logging.DEBUG)

import yaml
cred = yaml.load(open("credentials.yml"))["google"]
client_id = cred['id']
client_secret = cred['secret']

redirect_uri = 'https://localhost:5000/login/google'

# OAuth endpoints given in the Google API documentation
authorization_base_url = "https://accounts.google.com/o/oauth2/auth"
token_url = "https://accounts.google.com/o/oauth2/token"
scope = [
     "https://www.googleapis.com/auth/userinfo.email",
     "https://www.googleapis.com/auth/userinfo.profile"
 ]

from requests_oauthlib import OAuth2Session
google = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)

# Redirect user to Google for authorization
authorization_url, state = google.authorization_url(authorization_base_url,
     # offline for refresh token
     # force to always make user click authorize
     access_type="offline", approval_prompt="force")
print('Please go here and authorize,', authorization_url)

# Get the authorization verifier code from the callback url
redirect_response = input('Paste the full redirect URL here:')

import requests.auth
class HTTPNullAuth(requests.auth.AuthBase):
	def __call__(self, response): return response

# Fetch the access token
google.fetch_token(token_url, client_secret=client_secret,
         authorization_response=redirect_response, auth=HTTPNullAuth())

# Fetch a protected resource, i.e. user profile
r = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
print(r.content)
