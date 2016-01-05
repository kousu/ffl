# from https://requests-oauthlib.readthedocs.org/en/latest/examples/facebook.html
app_id = '939310079547587'
app_secret = 'b3649fb08e6c25c56d3acf7a99382b35'

authorization_base_url = 'https://www.facebook.com/dialog/oauth'
token_url = 'https://graph.facebook.com/oauth/access_token'
redirect_uri = 'https://localhost:5001/oauth2/facebook'     # Should match Site URL

from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
facebook = OAuth2Session(app_id, redirect_uri=redirect_uri)
facebook = facebook_compliance_fix(facebook)
S = facebook

if __name__ == '__main__':
	authorization_url, state = facebook.authorization_url(authorization_base_url)
	print('Please go here and authorize,', authorization_url)
	
	redirect_response = input('Paste the full redirect URL here:')
	
	print("facebook.fetch_token(%r, client_secret=%r, authorization_response=%r)" % (token_url,app_secret,redirect_response))
	facebook.fetch_token(token_url, client_secret=app_secret,
        	             authorization_response=redirect_response)

	from pprint import *
	pprint(facebook.get('https://graph.facebook.com/me?').json())