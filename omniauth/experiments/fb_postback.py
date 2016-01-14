# adapted from https://requests-oauthlib.readthedocs.org/en/latest/examples/facebook.html
"""
 this is an experiment to see if it's reasonable to

 if that works, then the bigger project will be to make an FB App that turns FB into a feed reader, like Tumblr and LJ already are
 (there are, here and there, e.g. TwitterFeed, sites which relay RSS to FB, but those are not own-your-data friendly: they are focused on public-only posts because they are aimed at marketters trying to efficiently spam)
 (step one: a site
  step two: make it possible?
  or maybe the better flow is simply that if

YES!
POST https://graph.facebook.com/v2.5/me/feed
[headers]

{'message': "This is a private test post", 'link': 'https://google.tw', 'privacy': {'value': 'SELF'}}


the key thing is the 'privacy': 'SELF' thing, that's how you make a totally private post.


But there's a catch
You need to publish_actions scope (i.e. permission: https://developers.facebook.com/docs/facebook-login/permissions#reference-publish_actions)
 in order to make posts. 

 You can test that this JSON string will work from the Graph API Explorer which has all permissions available
 and you can test it with this script, so long as the account you OAuth to is listed under under https://developers.facebook.com/apps/<app_id>/roles/
 but to have anyone else use it you have to submit it for https://developers.facebook.com/apps/<app_id>/review-status/,
 which is a manual process where they check what you're doing. Besides the tedium of this, their rules are:
 * DON'T Automatically publish stories without the person being aware or having control.
 * DON'T Pre-fill the user message parameter of posts with content a person t create, even if the person can edit or remove the content before sharing.didn
 which are actually really great. I'm really happy to see Facebook taking privacy seriously. But these rules totally kill being able to hack your facebook feed into a feedreader.
 also it's a shitty feedreader anyway: you have to go to your own wall in order to see posts reliably; they *do* show up in the your main feed, but because they're private and have no interactions over them they get buried rapidly by the algorithm)
 so basically the upshot is: this shit isn't going to work. siiigh.
"""
import yaml
cred = yaml.load(open("credentials.yml"))["facebook"]
app_id = cred['id']
app_secret = cred['secret']

import logging
logging.basicConfig(level=logging.DEBUG)

authorization_base_url = 'https://www.facebook.com/dialog/oauth'
token_url = 'https://graph.facebook.com/oauth/access_token'
redirect_uri = 'https://localhost:5000/oauth2/facebook'     # Should match Site URL

from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
S = OAuth2Session(app_id, redirect_uri=redirect_uri, scope=["publish_actions"])
S = facebook_compliance_fix(S)


if __name__ == '__main__':
	authorization_url, state = S.authorization_url(authorization_base_url)
	print('Please go here and authorize,', authorization_url)
	
	redirect_response = input('Paste the full redirect URL here:')
	
	S = OAuth2Session(app_id, redirect_uri=redirect_uri)
	S = facebook_compliance_fix(S)
	S._state = state
	
	print("S.fetch_token(%r, client_secret=%r, authorization_response=%r)" % (token_url,app_secret,redirect_response))
	S.fetch_token(token_url, client_secret=app_secret,
        	             authorization_response=redirect_response)
	
	
	from pprint import *
	perms = S.get("https://graph.facebook.com/v2.5/me/permissions").json()
	print("User granted these perms:")
	pprint(perms)
	
	print("Trying to make a public post:")
	pprint(S.post('https://graph.facebook.com/v2.5/me/feed', {'message': "This is a public test post from state %s" % S._state, 'link': 'https://cnn.com'}).json())

	print("Trying to make a private post:")
	pprint(S.post('https://graph.facebook.com/v2.5/me/feed', json={'message': "This is a private test post from state %s" % S._state, 'link': 'https://cnn.com', 'privacy': {'value': 'SELF'}}).json())

