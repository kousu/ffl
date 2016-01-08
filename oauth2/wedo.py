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


[x] Write providers as classes instead of a dict
[x] Extract user details to a useful user object
 [x] avatars too
[ ] Make templates which render a login selector that jumps you to the correct login flow
 - use https://github.com/lipis/bootstrap-social/; it's pure-CSS so I can render it without javascript hacks
  [ ] OAuth1
  [x] OAuth2
  [ ] OpenID
  [ ] Email auth
  [ ] User/password auth (?)
[ ] Support scopes (---do I want to do this? really? if the goal is social sign in then I should never need any but the default scope)
[ ] Auto-load compliance fixes
[ ] Save avatars server-side and serve them from there (to avoid creating a tracker inadvertantly)
  -- Make sure to think through the privacy implications for subscribers.  If you copy their avatar they lose control of it!
[ ] Support other web frameworks besides Flask
[ ] Support non-web ??
[ ] Cheat: translate Facebook app-scoped UIDs to global UIDs
  -- apparently Facebook didn't actually make app-scoped IDs local to each app
  and they provide "https://www.facebook.com/app_scoped_user_id/<id>
  the catch is you have to be logged in to follow it
  but you can use *any* account to follow the link and get jumpped over to facebook.com/<username> (and by screen-scraping you can also find the global user ID)
"""

import yaml

from urllib.parse import *
import requests
from requests_oauthlib import *
from requests_oauthlib.compliance_fixes import facebook_compliance_fix

from flask import *

from pprint import pformat, pprint

import logging
logging.basicConfig(level=logging.DEBUG) # turn up logging so we can see inside requests_oauthlib
	# note that this logger is *not* the same as the Flask logger



app = Flask(__name__) #TODO: use Blueprints (but Blueprints are dumb, argh)
app.debug = True

# inputs: authentication provider, our client id and secret as registered with that provider, and a callback which takes the OAuth-authenticated requests Session and uses it to get and outputs the userid
# outputs: a string <provider>:<userid>
# userid is a string. it is probably a username, but for some sites (e.g. facebook, myspace) it is an ID number because the user names are in flux
#  TODO: return an account object of some sort, at least containing a friendly name and possibly email/avatar 


#

# a useful quirk of OAuth is that the callback URL *can be localhost*, because the auth code is passed via the client


class User(object):
	"""
	Base class for Represent a user, a single person, or at least a single identity.
	This class does not enforce any sort of constraints: *SECURITY IS NOT HERE*. You must make sure not to hand out User objects unless you have some external sort of auth.
	
	* provider is a string identifying the identity server ("github", "facebook", these should be pretty globally unique: use https://github.com/lipis/bootstrap-social/ as a guideline)
	 * you could also use non-providers, like "anonymous", "local", "mailto" or "xmpp", so long as you have a way for the user to prove they own the address
	* id uniquely identifies the user within the world of `provider`
	* .urn combines these into a URN as "$provider:$id"
	
	The optional extra fields are:
	* login is the username someone has on a site; this is typically different than their ID number, and lots of sites even allow changing it.
	* name is a full name, which should be displayed
	* ~avatar should be a URL (note: data: urls with encoded images are allowed here, if that's what the site gives or if you want to rip the image locally.
	Feel free to extend this class with more details if appropriate.
	 extension ideas:
		- something that holds onto the OAuth token

	"""
	
	@classmethod
	def loadJSON(cls, data):
		data = json.loads(data)
		return cls(**data)
	
	def dumpJSON(self):
		return json.dumps(self.__dict__)
	
	
	def __init__(self, provider, id, login=None, name=None, avatar=None):
		self.provider = provider
		self.id = id
		self.login = login
		self.name = name
		self.avatar = avatar
	
	@property
	def urn(self):
		"""
		Return a globally unique ID string for this user.
		This is what should be used as a primary key in a database
		"""
		return "%s:%s" % (self.provider, self.id)


class Provider(object):
	"""
	Base class for authentication providers.
	"""
	pass


class MailTo(Provider):
	# uhh, this isn't an OAuth provider sooooo I need to rethink stuff a bit
	# to prove you own an email, we send a token to that address and you paste it back to us,
	# either by clicking a link with the token embedded or by copy-pasting it directly at us
	pass

class Local(Provider):
	# TODO
	# this would be the username/password option, I guess
	pass

class Anonymoose(Provider):
	# TODO
	# this is the pseudoanonymous option, where there is no way to prove
	# my idea is: click once on a subscribe link, possibly fill in a profile (that is, name and avatar, but not login!) and an account is generated for you, along with an auth token
	# then to get back in you must click the auth token link. there's no username or password
	pass



class OAuth2Provider(Provider):
	"""
	sub-base class for OAuth2 identity providers

	
	Holds the remote OAuth endpoints in {auth,token}_url,
	and at init stores the app_{id, secret} strings that you need to get by registering a developer account with the OAuth provider,
	and has the whoami() method which is called after OAuth completes to extract account details
	 (because OAuth is an authorization not, directly, an authentication protocol)
	
	Naming matters! Your subclasses must match the names shared between oauth-dropins/bootstrap-social/, because it gets scraped to generate identifying strings.
	 (but you can choose your own capitalization; they are .lower()ed before use)

	This clusterfuck is because OAuth couldn't just spec something like "OAuth is a RESTful protocol and it MUST live at site.com/oauth/". bastards.
	 each site's URLs have to be researched, and kept up to date,
	 and further each site has to have custom code for extracting identity information once you've got an auth token.
	"""
	auth_url = None
	token_url = None
	
	def __init__(self, id, secret):
		self.app_id = id
		self.app_secret = secret #TODO: check types
	
	@staticmethod
	def whoami(session):
		assert isinstance(session, requests.Session)
		raise NotImplementedError

#OAuth-dropins decided to use inheritence, not composition: each provider subclasses 
# prefer composition to inheritence!

class Github(OAuth2Provider):
	#  # https://developer.github.com/v3/oauth/
	auth_url = 'https://github.com/login/oauth/authorize'
	token_url = 'https://github.com/login/oauth/access_token'
	
	@staticmethod
	def whoami(session):
		"""
		returns:
		id: numeric account ID
		name: freeform real-name
		login: username (note! github allows changing this! so treat it like a freeform name!)
		"""
		profile = session.get("https://api.github.com/user").json()
		logging.debug("Received this profile from github:\n--------------\n%s\n--------------", pformat(profile))
		return User("github", profile['id'], profile['login'], profile['name'], profile['avatar_url']+"&s=50") # the &s=50 makes github resize the picture to 50x50 before replying (this matches the only size Facebook will give out)
		#return {k: v for k,v in profile.items() if k in ['id', 'name', 'login']}


class Facebook(OAuth2Provider):
	"""
	https://developers.facebook.com/docs/facebook-login and
	https://requests-oauthlib.readthedocs.org/en/latest/examples/facebook.html
	
	To get Facebook working, first you need to set your account to developer mode, then [verify your account](https://www.facebook.com/help/167551763306531#How-do-I-verify-my-developer-account?),
	then register an app at https://developers.facebook.com/apps/
	in the app, click "Add Platform", choose "Web", type a URL (arggggh) to lock the oauth to that URL. However, you *can* set this to localhost.
	"""
	auth_url = 'https://www.facebook.com/dialog/oauth'
	token_url = 'https://graph.facebook.com/oauth/access_token'
	
	@staticmethod
	def whoami(session):
		"""
		id: numeric account ID (note! IDs are *app scoped*)
		name: freeform real-name
		
		App-Scoping: <https://developers.facebook.com/docs/graph-api/reference/user/>: " This ID is unique to each app and cannot be used across different apps."
		  i.e. the ID this gives is *not* the ID you use in https://facebook.com/profile.php?id=<....>
		 to prevent apps (easily) colluding and tracking users.
		 you can ask for field "link" but it just gives like https://www.facebook.com/app_scoped_user_id/297049897162674.
	         now, that link does in fact send you to the right place but requires being logged in with a personal account, which is a bitch and probably against the ToS.
		 (however, it doesn't require being logged in under any particular account: any FB account can follow that link and  get the username, *and* the original ID...which means it's a security hole that they'll probably notice and close within the year)
		"""
		profile = session.get("https://graph.facebook.com/v2.5/me?fields=id,name,picture{url}").json()
		username = None # <-- this can't be recovered from /me
		# NB: by using /me/picture it might be possible to get a larger image:
		#   https://developers.facebook.com/docs/graph-api/reference/user/picture/
		#   however so far everything i've tried has redirected me back to the 50x50 one, so I'll just live with that
		return User("facebook", profile['id'], username, profile['name'], profile['picture']['data']['url']) #why picture.data.url? why not, says Facebook.
		#return {k: v for k,v in profile.items() if k in ['id', 'name']}

# Make a big lookup table of all available providers
# Now, the architectually nice way to do this would be with an event listener:
# on creation of each provider subclass, record it automatically
# But to do that means remembering how metaclasses work.
# This is almost as fast, and simpler for me to write.
PROVIDERS = {cls.__name__.lower(): cls for cls in (e for e in locals().values() if isinstance(e,type)) if issubclass(cls, Provider)}
del PROVIDERS['provider'] #remove cruft



def load_oauth2_credentials(fname="credentials.yml"):
	"merge on-disk app credentials into global PROVIDERS"
	"beware: OAuth2Provider is written assuming you'll instantiate it with app_{id,secret}, but instead this attaches directly to the class; the only method is static, so either way works right now"
	credentials = yaml.load(open(fname))
	global PROVIDERS
	for provider in list(PROVIDERS.keys()): #listification is because we're editing the dict as we loop over it so we need to protect
		if issubclass(PROVIDERS[provider], OAuth2Provider):
			if provider not in credentials or 'id' not in credentials[provider] or 'secret' not in credentials[provider]:
				#app.logger.warn("Missing '%s' app credentials." % (provider,))
				del PROVIDERS[provider]
			else:
				PROVIDERS[provider].app_id = credentials[provider]['id']
				PROVIDERS[provider].app_secret = credentials[provider]['secret']
	app.logger.info("Available authorization providers:\n%s", "\n".join("* " + e for e in sorted(PROVIDERS.keys())))

	


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


# Since I don't have a database set up, store the entire user in the session cookie.
# To do this transparently would require somehow overriding flask.session.SecureCookieSessionInterface.serializer to understand more types
# which sounds.. hard
# so instead I'm just going to manually save/load to JSON
# This bloats the session cookie, but hoooooopefully not by too much.

@app.before_request
def load_user():
	global current_user
	current_user = None
	if 'user' in session:
		current_user = User.loadJSON(session['user'])

def login(user):
	"log user in. This is a mock for Flask-Login's login()"
	session['user'] = user.dumpJSON()

def logout():
	"log user out. This is a mock for Flask-Login's login()"
	if 'user' in session:
		del session['user']



@app.route("/oauth2/<provider>")
def oauth2(provider):
	"""
	An endpoint which handles client (i.e. application) side OAuth.
	
	To login, a user GETs this endpoint.
	Then we look up the proper provider in our backend and redirect them over there.
	The provider (should) asks the client to auth us, and if so redirects them back
	to us *at the same endpoint* (which is unusual: most OAuth flows have separate endpoints, one for the initial click, one for the callback, and one for the finishing step)
	
	"""
	try:
		provider = PROVIDERS[provider]
	except KeyError:
		return "Unsupported OAuth provider.", 404
	
	
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
	S = OAuth2Session(provider.app_id,
	                  redirect_uri=urlstrip(request.url))
	
	
	if provider == 'facebook': #HACK
		# TODO: scan requests_oauthlib.compliance_fixes to find all the fixes and apply the correct one
		# requires assuming that we choose consistent provider names, but I think we can probably make that happen
		S = facebook_compliance_fix(S) #arrrgh
	
	# We figure out if we're the initial click or a callback
	if request.args.get("code") is None:
		# Initial click
		url, session['oauth_state'] = S.authorization_url(provider.auth_url)
		app.logger.info("auth url = %s", url)
		#input("press enter to continue")
		return redirect(url)
	else:
		# Callback! Fetch a token!
		S._state = session['oauth_state']
		
		# NOTICE: we *don't* reload the state from the query string, instead it's from the session
		# this protects against CSRF by .....
		# (the actual check is buried in oauthlib.oauth2.rfc6749.parameters.parse_authorization_code_response())
		
		token = S.fetch_token(provider.token_url, authorization_response=request.url, client_secret=provider.app_secret)
		
		user = provider.whoami(S) #call the user-id extracting callback
		
		# TODO: provide a hook so that on login
		login(user)
		
		return redirect("/")


@app.route('/')
def index():
	if current_user:
		args = dict(current_user.__dict__) #copy
		args['urn'] = current_user.urn #this wasn't in the copy because it's a property. oh dear. leaky abstraction!
		return "Hello %(name)s. <img alt='%(name)s' title='%(name)s' src='%(avatar)s' />. Your ID to me is %(urn)s and your username over there is %(login)s." % args   +\
		       " <form action='%s' method='POST'><button>Logout</button></form>" % (url_for("logout"),)
	else:
		return "Try <a href='%s'>logging in</a>." % (url_for("oauth2", provider="github"))

@app.route('/logout', methods=["POST"])
def logout_view():
	"""
	# TODO: implement CSRF protection
	# ( this requires... WTForms? I think? )
	"""
	logout()
	return redirect("/")

if __name__ == '__main__':
	app.debug = True
	app.secret_key = "butts"
	
	load_oauth2_credentials()

	import ssl
	t = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	t.load_default_certs() # OAuth2 specs that you MUST use TLS, because for simplicity it doesn't do any crypto itself. This is probably a good idea, but it does make testing tricky.
	t.load_cert_chain("localhost.crt","localhost.key")
	app.run(use_reloader=False, host="0.0.0.0", ssl_context=t)
