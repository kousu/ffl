#!
"""
OAuth is a little shit
Unlike OpenID and email addresses, OAuth doesn't *authenticate* a user to a "client"(==webapp), it /authorizes/.
That is, it doesn't hand out a proof of identity, it hands out a (cryptographic) capability.
 You can always in principle turn a capability into an identity, by using it yo ask the authorization provider "what account is this?"
 but this is *not* standardized because

Another way OAuth is a shit is that it demands each client register with each provider. Presumably this helps against brute-forcing,
 but it means that accepting social-auths becomes very expensive: each s
 and it means that it is effectively impossible to set up your own custom OAuth provider

Another way it's a shit is that it has three or four different algorithms:
 one for web browsers
 one for mobile apps
 one for
each with different security guarantees(!) which means it's up to each provider to choose which to support

Another: the CSRF token is *optional*. If you just delete it from the oauth call
Another: it's not standardized if redirect_url should be stored server-side or passed


Now, the reason for this is that it was developed by corps wanting to mashup the data in their silos
without passing around full credentials. That makes sense. But the "login" use case totally got swamped.
Facebook sells their login as "social auth" and that's 99% of what people use it for:
 Soundcloud and New York Times and a gazillion other sites which get your Facebook name, photo, and id and use these to let you log in without having to secure their own accounts infrastructure.

"""

"""
TODO:

This is meant to only be an *identity* provider.
This is meant to outdo http://psa.matiasaguirre.net/, which is ridiculously overengineered.


[ ] Write providers as classes instead of a dict
[ ] Extract user details to a useful user object~
[ ] Make templates which render a login selector that jumps you to the correct login flow
 - use https://github.com/lipis/bootstrap-social/; it's pure-CSS so I can render it without javascript hacks
  [ ] OAuth1
  [ ] OAuth2
  [ ] OpenID
  [ ] Email auth
  [ ] User/password auth (?)
[ ] Support scopes (---do I want to do this? really? if the goal is social sign in then I should never need any but the default scope)
[ ] Auto-load compliance fixes
[ ] Support other web frameworks besides Flask
[ ] Support non-web ??

"""

import yaml

from urllib.parse import *
import requests
from requests_oauthlib import *
from requests_oauthlib.compliance_fixes import facebook_compliance_fix

from flask import *

from pprint import pformat



app = Flask(__name__) #TODO: use Blueprints (but Blueprints are dumb, argh)
app.debug = True

# inputs: authentication provider, our client id and secret as registered with that provider, and a callback which takes the OAuth-authenticated requests Session and uses it to get and outputs the userid
# outputs: a string <provider>:<userid>
# userid is a string. it is probably a username, but for some sites (e.g. facebook, myspace) it is an ID number because the user names are in flux
#  TODO: return an account object of some sort, at least containing a friendly name and possibly email/avatar 


#

# a useful quirk of OAuth is that the callback URL *can be localhost*, because the auth code is passed via the client


def github_userid(session):
	"""
	id: numeric account ID
	name: freeform real-name
	login: username (note! github allows changing this! so treat it like a freeform name!)
	"""
	profile = session.get("https://api.github.com/user").json()
	return {k: v for k,v in profile.items() if k in ['id', 'name', 'login']}

def facebook_userid(session):
	"""
	id: numeric account ID (note! IDs are *app scoped*)
	name: freeform real-name
	
	App-Scoping: <https://developers.facebook.com/docs/graph-api/reference/user/>: " This ID is unique to each app and cannot be used across different apps."
	  i.e. the ID this gives is *not* the ID you use in https://facebook.com/profile.php?id=<....>
	 to prevent apps (easily) colluding and tracking users.
	 you can ask for field "link" but it just gives like https://www.facebook.com/app_scoped_user_id/297049897162674
         which does send you to the right place but requires being logged in(??) on top of having an access token, which is a bitch and probably against the ToS.
	So it doesn't seem possible.
	"""
	profile = session.get("https://graph.facebook.com/v2.5/me").json()
	return {k: v for k,v in profile.items() if k in ['id', 'name']}

# this clusterfuck is because OAuth couldn't just spec something like "OAuth is a RESTful protocol and it MUST live at site.com/oauth/". bastards.
# these details extracted by dicking around
# TODO: use https://lipis.github.io/bootstrap-social/
PROVIDERS = {
 # https://developers.facebook.com/docs/facebook-login and
 # https://requests-oauthlib.readthedocs.org/en/latest/examples/facebook.html
 # To get Facebook working, first you need to set your account to developer mode, then [verify your account](https://www.facebook.com/help/167551763306531#How-do-I-verify-my-developer-account?),
 # then register an app at https://developers.facebook.com/apps/
 # in the app, click "Add Platform", choose "Web", type a URL (arggggh) to lock the oauth to that URL. However, you *can* set this to localhost.
 'facebook': {
   'auth_url': 'https://www.facebook.com/dialog/oauth',
   'token_url': 'https://graph.facebook.com/oauth/access_token',
   'whoami': facebook_userid,
  },
 
 # https://developer.github.com/v3/oauth/
 'github': {
    'auth_url': 'https://github.com/login/oauth/authorize',
    'token_url': 'https://github.com/login/oauth/access_token',
    'whoami': github_userid,
  }
}


def load_credentials(fname="credentials.yml"):
	" merge on-disk app credentials into global PROVIDERS "
	credentials = yaml.load(open(fname))
	
	for provider in list(PROVIDERS.keys()): #listification is because we're editing the dict as we loop over it so we need to protect
		if provider not in credentials or 'id' not in credentials[provider] or 'secret' not in credentials[provider]:
			#app.logger.warn("Missing '%s' app credentials." % (provider,))
			del PROVIDERS[provider]
		else:
			PROVIDERS[provider]['app_id'] = credentials[provider]['id']
			PROVIDERS[provider]['app_secret'] = credentials[provider]['secret']
	app.logger.info("Available authorization providers:\n%s", "\n".join("* " + e for e in sorted(PROVIDERS.keys())))

if __name__ == '__main__':
	load_credentials()
	


# also, I guess we need a callback to happen when someone auths


# XXXX is there any way to make this work without tying it to a specific web framework?
# what about web-less backends (I know there's the mobile
# that's sort of irritating

# This only implements the Web authorization flow, which is the most common one.
# There are three parties: user, provider, client.
# The goal is for user (a person) to grant client (a website or mobile app, possibly also the plugins like Windows Gadgets or Gnome Shell plugins) a capability to use user's data that is held by provider.
#  (note: the capability granted is just a string; it is up to *each* provider to maintain)
# In this flow:
# A) user clicks "sign in with provider.com" on client.com
# B) client.com grabs a temporary "request token" from provider.com, and uses it to generate
# C) client.com tells user "go to provider.com/auth/?response_type=code&client_id=<provider.com's pre-registered ID for client.com>"
#     (you can also tack on scopes=x,y,z here; a 'scope' is just a string, but the idea is each scope corresponds to a set of permissions as defined by provider.com, and each provider is *supposed* to but there is no way to enforce that they will list the scopes being granted to user before granting happens)
# D) provider.com asks user to grant or deny access. if granted:
# E) provider.com tells user "go to client.com/callback?code=<.....>"
# F) client.com takes the given code and goes to

# Question: why does OAuth require swapping the code for an access token? Why not just hand back an access token?
#  a) because >????
# --- you could maybe fix this with public key crypto, couldn't you?


def urlstrip(url):
	# return url # if you uncomment this, Facebook breaks because you end up sending two different redirect_uris to it. I'm hanging onto this for now because 
	"normalize a URL to just the REST-ful object path part (i.e. scheme, host, path)"
	(scheme, netloc, path, _, _, _) = urlparse(url)
	return urlunparse((scheme, netloc, path, "", "", ""))


def logged_in(u):
	session['userid'] = u
	app.logger.info("%s logged in.", u)
	return redirect("/")

import logging
logging.basicConfig(level=logging.DEBUG) # turn up logging so we can see inside requests_oauthlib


@app.route("/oauth2/<provider>")
def oauth2(provider):
	"""
	An endpoint which handles client (i.e. application) side OAuth.
	
	To login, a user GETs this endpoint.
	Then we look up the proper provider in our backend and redirect them over there.
	The provider (should) asks the client to auth us, and if so redirects them back
	to us *at the same endpoint* (which is unusual: most OAuth flows have separate endpoints, one for the initial click, one for the callback, and one for the finishing step)
	
	"""
	if provider not in PROVIDERS:
		return "Unsupported OAuth provider.", 404
	
	class p: pass;
	p = p()
	p.__dict__.update(PROVIDERS[provider]) #import token_url, app_id, etc into the local namespace
	
	# An OAuth "app" is an account stored at provider which consists of
	#  at least (name, app_id, app_secret, callback)
	# redirect_uri is callback_uri, and it is where.
	# Providers have different rules about what callback is; Github wants it to be a prefix of a URI that you'll send as redirect_uri
	# Facebook lets you leave it blank but makes you fill in a domain name and checks that at least that matches.
	# 

	# We want this one endpoint to handle *all* the callbacks for all the providers,
	# so we set redirect_uri to request.url (e.g. https://localhost:5000/oauth2/facebook)
	# but we need it normalized because during the callback we get something like https://localhost:5000/oauth2/facebook?code=AQABl4ziZe9QsS1ZmT9QS1K5gZFV88M7YD5F0jGHcfuFKxFAF1QvqamERgXYSyHfYSFwnyrcyvmx1lQnJPMucUVI0VDr4OQIbHDafsnGKed65A6OLWbgH5SxQIu--IWC14bDvUMeIP5QcXgHKa5RTG755YqDGBDSn9fUxI_RioLrwzLyMiSad1E2ygK4Slofh6P0gcKZ4GDvAnaQHLFrBDhtZ7o-w-Wgv2VWkdjvsrrS75uFfa0-Ms_Cbg8-tLXJO7FGvfMJRZ1fJZo6x5_l0C3SvVIdNthwEf4T_Z0Ya7bg4dK9MHnHkTijhiETIHBvebwTRFm3FTgMB1R5BBqk8fax&state=64z2IR2IYZJ1l96DckFgmnNbnJcVjQ
	# which is technically wrong, certainly wasteful, and actively pisses off at least Facebook who says "this URL doesn't match!" and fails the fetch_token()
	S = OAuth2Session(p.app_id,
	                  redirect_uri=urlstrip(request.url))
	
	
	if provider == 'facebook': #HACK
		# TODO: scan requests_oauthlib.compliance_fixes to find all the fixes and apply the correct one
		# requires assuming that we choose consistent provider names, but I think we can probably make that happen
		S = facebook_compliance_fix(S) #arrrgh
	
	# We figure out if we're the initial click or a callback
	if request.args.get("code") is None:
		# Initial click
		url, session['oauth_state'] = S.authorization_url(p.auth_url)
		app.logger.info("auth url = %s", url)
		#input("press enter to continue")
		return redirect(url)
	else:
		# Callback! Fetch a token!
		S._state = session['oauth_state']
		
		# NOTICE: we *don't* reload the state from the query string, instead it's from the session
		# this protects against CSRF by .....
		# (the actual check is buried in oauthlib.oauth2.rfc6749.parameters.parse_authorization_code_response())
		
		token = S.fetch_token(p.token_url, authorization_response=request.url, client_secret=p.app_secret)
		
		user = p.whoami(S) #call the user-id extracting callback
		userid = user['id']
		userid = "%(provider)s:%(userid)s" % locals() # tag the userid with the site it came from, as a URN
		
		# call the logged-in callback
		# this needs to be like Flask-Login login(), except it has to also tolerate creating accounts
		return logged_in(userid)


@app.route('/')
def index():
	if 'userid' in session:
		return "Hello %s.  <form action='%s' method='POST'><button>Logout</button></form>" % (session['userid'], url_for("logout"))
	else:
		return "Try <a href='%s'>logging in</a>." % (url_for("oauth2", provider="github"))

@app.route('/logout', methods=["POST"])
def logout():
	if 'userid' in session:
		del session['userid']
	return redirect("/")

if __name__ == '__main__':
	app.debug = True
	app.secret_key = "butts"
	
	import ssl
	t = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	t.load_default_certs() # OAuth2 specs that you MUST use TLS, because for simplicity it doesn't do any crypto itself. This is probably a good idea, but it does make testing tricky.
	t.load_cert_chain("localhost.crt","localhost.key")
	app.run(use_reloader=False, host="0.0.0.0", ssl_context=t)
