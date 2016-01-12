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


[ ] Patch bootstrap-social to cover pseudoanon, email, user/pass, and phones
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
  [x] pseudoanon
  [ ] sms
[ ] Glitch:
 - tumblr (on OAuth1) and google (on OAuth2) both for some reason *always* re-prompt the user
   but the other sites log you in smoothly
   if google is always going to reprompt, why does it have {access_type="offline", approval_prompt="force"} as options?
    -- I think maybe if I pass ?access_type=offline then google will save the thing? maybe? hm.
[ ] Support scopes (---do I want to do this? really? if the goal is social sign in then I should never need any but the default scope)
[ ] Auto-load compliance fixes
  # TODO: [e for e in dir(requests_oauthlib.compliance_fixes) if e.endswith("compliance_fix")]
[ ] Save avatars server-side and serve them from there (to avoid creating a tracker inadvertantly)
  -- Make sure to think through the privacy implications for subscribers.  If you copy their avatar they lose control of it!
  -- in fact, Disconnect.me blocks the Twitter avatars specifically because they are also trackers
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


WORDLIST = "/usr/share/dict/words"

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
	
	
	def __init__(self, provider, userid, login=None, display_name=None, avatar=None):
		self.provider = provider
		self.userid = userid
		self.login = login
		self.display_name = display_name
		self.avatar = avatar
	
	@property
	def id(self):
		"""
		Return a globally unique ID string for this user.
		This is what should be used as a primary key in a database
		"""
		return "%s:%s" % (self.provider, self.userid)


class Provider(object):
	"""
	Base class for authentication providers.
	"""
	name = None
	icon = None #shortcode used to refer to this provider in URLs and CSS and such
	 #ah, separate presentation from logic: it might not be possible to use the same code across bootstrap-social and requests-oauthlib and elsewhere...

	@staticmethod
	def whoami(session):
		assert isinstance(session, requests.Session)
		raise NotImplementedError



import oath
from subprocess import Popen
class SMS(Provider):
	"""
		
	Setting up on Vitelity.net is tricky.
	0) login to https://portal.vitelity.net
	1) provision a number (a "DID")
	2) find the number's status page
	3) click "add SMS" on it (whatever Vitelity has renamed it now)
	4) try the XMPP interface: login as <number>@s.ms and try sending a message to <othernumber>@sms (note: they dropped the period in the vhost name, just to be confusing)
	  if that doesn't work, wait an hour
	  if it still doesn't work, open a support ticket, and wait
	5) Configure your account for API access from the IP you're sitting behind (link???)
	
	Thought they they provide an `API <http://apihelp.vitelity.net/#sendsms>` they say "Bots and scripts not allowed" on the SMS config page
	this is probably just covering themselves against running up against CTIA regulations:
	  http://www.experian.com/blogs/marketing-forward/2013/01/02/sms-compliance-what-you-dont-know-can-hurt-you/
	but, so long as you're not /spamming/ (and auth is hardly spam) you should be legal. probably. IANAL.
	or you could just set up an xmpp client (`sj? <https://github.com/younix/sj>`). a layer of indirection, but arguably faster to config.
	
	other providers:
	- Clickatell
	- SMSGlobal
	- Twilio (probably the most mature, at the moment)

	TODO: figure out a way to make sure these requests are rate-limited (besides waiting for your SMS prepaid credits to run out)
	"""
	# i.e. SMS
	# <i class="fa fa-mobile"></i> https://fortawesome.github.io/Font-Awesome/icon/mobile/
	name = "Mobile Phone"
	icon = "mobile" #code = "tty" is also good
	
	@staticmethod
	def normalize_number(tel):
		# TODO: write this
		# make sure, give an error on bad formats, etc
		return tel
	
	@classmethod
	def handle(self):
		# this code is confusing because it handles three flows simulatenously
		# it would be a *lot* cleaner as a coroutine, but Flask doesn't do coroutines.
		if request.method == "GET":
			return render_template("login_sms.html", mode="get_id")
		elif request.method == "POST":
			
			
			if 'id' in request.form:
				# first reply: get the SMS number
				session['sms_auth_id'] = self.normalize_number(request.form['id'])
				session['sms_auth_name'] = request.form['name']
			
			
			# generate a OATH key; we use the app key plus the user id, so that a) no one can make the key except us b) the keys are unique to each user
			# potential attack: give a different
			# note! we *don't* give the client the key!!
			key = binascii.hexlify(("%s:%s" % (session['sms_auth_id'], app.secret_key)).encode('utf-8')).decode('ascii')
			
			if 'id' in request.form:
				assert 'oath' not in request.form
				
				# send an SMS
				Popen(["./sms", session['sms_auth_id'], "Your code for %s is %s" % (request.url, oath.totp(key,period=90))]) #Note: we *don't* wait on this to finish before responding to the user, because sms is slow and the totp code only lasts 30 seconds anyway.
				
				return render_template("login_sms.html", mode="get_oath")
			elif 'oath' in request.form:
				id = session.pop('sms_auth_id')
				name = session.pop('sms_auth_name')

				passed, _ = oath.accept_totp(key, request.form['oath'], period=90)
				if not passed:
					flash("That oath code didn't work, enter another or <a href='%s'>start again</a>." % (url_for("login",provider=self.__name__.lower()),))
					return render_template("login_sms.html", mode="get_oath")
				
				login_user(User(self.__name__.lower(), id, None, name, None))
				return redirect("/")
	

class Email(Provider):
	# uhh, this isn't an OAuth provider sooooo I need to rethink stuff a bit
	# to prove you own an email, we send a token to that address and you paste it back to us,
	# either by clicking a link with the token embedded or by copy-pasting it directly at us
	name = "Email"
	icon = "envelope"

class Local(Provider):
	# TODO
	# this would be the username/password option, I guess
	name = "Username/Password"
	icon = "sign-in"


class Pseudoanon(Provider):
	# TODO
	# this is the pseudoanonymous option, where there is no way to prove
	# my idea is: click once on a subscribe link, possibly fill in a profile (that is, name and avatar, but not login!) and an account is generated for you, along with an auth token
	# then to get back in you must click the auth token link. there's no username or password
	
	with open(WORDLIST) as o:
		logging.info("Loading wordlist %s", WORDLIST)
		_words = list(set(e.strip().lower().split("'")[0] for e in o)) #TODO: stem the words
		if len(_words) < 2**16:
			raise ValueError("Not enough words in '%s' for us: we assume 16 bits worth (65536) of words." % (WORDLIST,))
	from uuid import uuid4 as _uuid4
	
	
	name = "Pseudoanomity"
	icon = "barcode" #"asterisk"?
	
	@classmethod
	def genid(self):
		id = self._uuid4()
		id = id.bytes
		# chunk id into 16, which is ~about~ the size of the wordlist
		id = [(id[i]<<8)|id[i+1] for i in range(0,len(id),2)]
		id = [self._words[c] for c in id]
		id = "-".join(id)
		return id
		
	
	@classmethod
	def handle(self):
		if request.method == "GET":
			# render a form
			session['partial_pseudoanon_id'] = self.genid() #securely generate an id serverside; don't let the user choose!
			return render_template("login_pseudoanon.html", id=session['partial_pseudoanon_id'], action=request.url)
		elif request.method == "POST":
			# read form results
			login_user(User(Pseudoanon.__name__.lower(), session['partial_pseudoanon_id'], session['partial_pseudoanon_id'], request.form['name'], None))
			del session['partial_pseudoanon_id']
			return redirect("/")


class OAuthProvider(Provider):
	auth_url = None
	token_url = None

	def __init__(self, id, secret):
		self.app_id = id
		self.app_secret = secret #TODO: check types


class OAuth1Provider(OAuthProvider):
	"""
	
	"""	
	# OAuth1 has an extra URL it needs to hit
	request_url = None
	

	@classmethod
	def handle(self):
		"""
		
		This code is almost identical to the OAuth2 flow. But it's just different enough making it that it needs to be separate but not so large that it's worth trying to factor.
			
		"""
		provider = self #HACKS
		
		# this code adapted from https://requests-oauthlib.readthedocs.org/en/latest/examples/tumblr.html
		S = OAuth1Session(provider.app_id,
		                  client_secret=provider.app_secret,
	       		          callback_uri=urlstrip(request.url)) #note: OAuth2 calls renamed this to "redirect_uri", just to complicate your life.
		
		if request.args.get("oauth_token") is None: #<-- FLASK
			session['oauth_state'] = S.fetch_request_token(provider.request_url)
			# construct the session-specific auth url at the provider to send the user over to
			auth_url = S.authorization_url(provider.auth_url)
			return redirect(auth_url) #<-- FLASK
		else:
			# restore the state from the first request
			S._populate_attributes(session['oauth_state'])
			del session['oauth_state']
			
			S.parse_authorization_response(request.url) #<-- FLASK
			S.fetch_access_token(provider.token_url)
			
			try:
				user = provider.whoami(S)
			except:
				return "You suck", 500

			login_user(user)
				
			return redirect("/")




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
	
	# TODO:
	# set up auto-token-refresh https://requests-oauthlib.readthedocs.org/en/latest/oauth2_workflow.html#third-recommended-define-automatic-token-refresh-and-update
	"""
	auth_url = None
	token_url = None
	scope = None
	
	def __init__(self, id, secret):
		self.app_id = id
		self.app_secret = secret #TODO: check types

	
	@classmethod
	def handle(self):
		"""
		An endpoint which handles client (i.e. application) side OAuth.
		
		To login, a user GETs this endpoint.
		Then we look up the proper provider in our backend and redirect them over there.
		The provider (should) asks the client to auth us, and if so redirects them back
		to us *at the same endpoint* (which is unusual: most OAuth flows have separate endpoints, one for the initial click, one for the callback, and one for the finishing step)
		
		"""
		provider = self #HACK
		
		# This code adapted from https://requests-oauthlib.readthedocs.org/en/latest/examples/facebook.html
		
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
		                  redirect_uri=urlstrip(request.url),
		                  scope=provider.scope)
		
	
		if provider == 'facebook': #HACK
			# TODO: scan requests_oauthlib.compliance_fixes to find all the fixes and apply the correct one
			# requires assuming that we choose consistent provider names, but I think we can probably make that happen
			S = facebook_compliance_fix(S) #arrrgh
	
		# We figure out if we're the initial click or a callback
		if request.args.get("state") is None:
			# Initial click
			# construct the session-specific auth url at the provider to send the user over to
			auth_url, session['oauth_state'] = S.authorization_url(provider.auth_url)
			return redirect(auth_url)
		else:
			# Callback! Fetch a token!
			S._state = session['oauth_state']
			del session['oauth_state']
			
			# NOTICE: we *don't* reload the state from the query string, instead it's from the session
			# this protects against CSRF because 
			# (the actual check is buried in oauthlib.oauth2.rfc6749.parameters.parse_authorization_code_response())
			token = S.fetch_token(provider.token_url, authorization_response=request.url, client_secret=provider.app_secret, client_id=provider.app_id, auth=HTTPNullAuth)
			
			try:
				user = provider.whoami(S)
			except:
				return "You suck", 500

			login_user(user)
				
			return redirect("/")

	

class Twitter(OAuth1Provider):
	"""
	Overview:  https://dev.twitter.com/web/sign-in/implementing
	Twitter is OAuth1.0a: https://dev.twitter.com/oauth

	
	create keys at:
	https://apps.twitter.com/
	 when you do this you *must* fill in something for the callback URL
	 (but it can just be, e.g., "http://facebook.com")
	because otherwise Twitter implicitly assumes you're making an app-key-only app
	 (which it sometimes slips up and calls a "desktop app") which only knows how to use app-level API keys
	 and doesn't allow you to use the user-level sign in thing ("Sign in with Twitter")
	 yet, Twitter fully respects *anything* you put in your own callback_url
	"""
	request_url = 'https://api.twitter.com/oauth/request_token'
	auth_url = 'https://api.twitter.com/oauth/authenticate'
	token_url = 'https://api.twitter.com/oauth/access_token'
	
	name = "Twitter"
	icon = "twitter"
	
	@classmethod
	def whoami(cls, session):
		# https://dev.twitter.com/rest/reference/get/account/verify_credentials
		profile = session.get("https://api.twitter.com/1.1/account/verify_credentials.json")
		profile.raise_for_status()
		profile = profile.json()
		
		id = profile['id']
		login = profile['screen_name']
		name = profile['name']
		avatar = profile['profile_image_url_https']
		return User(cls.icon, id, login, name, avatar)
	

class Tumblr(OAuth1Provider):
	"""
	Register at https://www.tumblr.com/oauth/apps
	Review https://www.tumblr.com/docs/api_agreement before registering.
	"""
	request_url = 'http://www.tumblr.com/oauth/request_token'
	auth_url = 'http://www.tumblr.com/oauth/authorize'
	token_url = 'http://www.tumblr.com/oauth/access_token'
	
	name = "Tumblr"
	icon = "tumblr"
	
	@staticmethod
	def whoami(session):
		# https://www.tumblr.com/docs/en/api/v2#user-methods
		r = session.get("https://api.tumblr.com/v2/user/info")
		r.raise_for_status()
		profile = r.json()['response']['user']
		# tubmlr accounts don't have avatars, *blogs* do
		# but each account has a *primary* blog whose avatar could in theory be extracted
		# also, the user info thing only gives a username, not an id, and I am 99% sure this can be easily changed...
		# but you work with what you've got
		# actually, since "identity" on tumblr basically comes down to <x>.tumblr.com and identities are supposed to be easily dumpable
		
		# find the avatar of the primary blog (this always exists; tumblr generates one if not set)
		app.logger.debug("GOT THIS PROFILE FROM TUMBLR:")
		pprint(profile)
		blog = [b for b in profile['blogs'] if b['primary']]
		if len(blog) != 1:
			raise Exception("Tumblr gave %d primary blogs for %d, but there should only every be 1." % (len(blog),profile['name']))
		blog = blog[0]
		
		# https://www.tumblr.com/docs/en/api/v2#blog-avatar
		# you can ask for different sizes by appending the pixels with /[pixels], e.g. avatar/512 gets the largest avatar
		# the default is a smallish
		avatar = session.get("https://api.tumblr.com/v2/blog/%(blog)s.tumblr.com/avatar" % {"blog": blog['name']})

		
		# tumblr doesn't give us user ids, so use the login as the userid
		# (which tbh I'd prefer to do for everyone, but the way that names can be thrown away makes me think twice..)
		# oh and for the avatar, we don't actually care about having the image data just yet, just the link is enough, so we can use .url:
		#                           id,           username,    name, avatar
		return User('tumblr', profile['name'], profile['name'], blog['name'], avatar.url)
	



class Google(OAuth2Provider):
	"""
	https://developers.google.com/identity/protocols/OAuth2
	
	Get keys at https://console.developers.google.com/#identifier
	Note that Google enforces that callback_url match the registered one, so you must set it right
	which makes deployment tedious
	
	# USEFUL: https://developers.google.com/oauthplayground
	# also https://developers.google.com/identity/protocols/googlescopes
	"""
	auth_url = "https://accounts.google.com/o/oauth2/auth"
	token_url = "https://accounts.google.com/o/oauth2/token"
	scope = ["https://www.googleapis.com/auth/userinfo.profile"]
	
	name = "Google"
	icon = "google"
	
	@classmethod
	def whoami(self, session):
		# TODO: switch to /v3
		profile = session.get('https://www.googleapis.com/oauth2/v1/userinfo')
		profile.raise_for_status()
		profile = profile.json()
		
		# 'email' is only in profile if we ask for userinfo.email

		return User(self.icon, profile['id'], None, profile['name'], profile['picture'])


#OAuth-dropins decided to use inheritence, not composition: each provider subclasses 
# prefer composition to inheritence!

class Github(OAuth2Provider):
	#  # https://developer.github.com/v3/oauth/
	auth_url = 'https://github.com/login/oauth/authorize'
	token_url = 'https://github.com/login/oauth/access_token'
	
	name = "GitHub"
	icon = "github"
	
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
	
	name = "Facebook"
	icon = "facebook"
	
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
del PROVIDERS['provider'] #remove abstract base classes
del PROVIDERS['oauthprovider']
del PROVIDERS['oauth1provider']
del PROVIDERS['oauth2provider']



def load_oauth_credentials(fname="credentials.yml"):
	"merge on-disk app credentials into global PROVIDERS"
	"beware: OAuth2Provider is written assuming you'll instantiate it with app_{id,secret}, but instead this attaches directly to the class; the only method is static, so either way works right now"
	credentials = yaml.load(open(fname))
	global PROVIDERS
	for provider in list(PROVIDERS.keys()): #listification is because we're editing the dict as we loop over it so we need to protect
		if issubclass(PROVIDERS[provider], (OAuth1Provider,OAuth2Provider)):
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
	
	global current_user #TOTALLY NOT THREAD (i.e. multi-user) SAFE LOLOLOLOLOLOLOLOLOLOL SECURITY HOLLLLLLE
	current_user = None
	try:
		if 'user' in session:
			current_user = User.loadJSON(session['user'])
	except Exception as exc:
		app.logger.warn(exc)
		pass

import binascii, hashlib

def login_user(user):
	"log user in. This is a mock for Flask-Login's login()"
	if not user.avatar:
		# generate a gravatar for them
		# https://en.gravatar.com/site/implement/hash/
		# gravatars are *supposed* to be a hash of an email address
		# but i'm explicitly not relying on knowing email addresses
		# so just generate *some* hash and use that
		hash = str(binascii.hexlify(hashlib.sha256(bytes(user.id,"utf-8")).digest()),"ascii") #
		user.avatar = "https://www.gravatar.com/avatar/%s.jpg" % (hash,)
	session['user'] = user.dumpJSON()

def logout_user():
	"log user out. This is a mock for Flask-Login's login()"
	if 'user' in session:
		del session['user']







import requests.auth
class HTTPNullAuth(requests.auth.AuthBase):
	"""
	Workaround for a bug in requests-oauthlib 2.9.1 and below.
	There's this line in OAuth2Session.fetch_token():
	  >         auth = auth or requests.auth.HTTPBasicAuth(username, password)
	 most providers ignore the Authorization: header when not asked for it, but Google at least is picky
	 and will 400 the request with no explanation
	 Newer requests-oauthlib now says
	  >       if (not auth) and username:
	  >          if password is None:
	  >            raise ValueError('Username was supplied, but not password.')
	  >          auth = requests.auth.HTTPBasicAuth(username, password)
	 which is a lot more reasonable.
	
	But 'auth or ....' is really annoying to hack around. I can't just set auth=None or auth="" or something.
	In lieu, This class pretends to be an auth thingy but actually is a no-op
	"""
	def __call__(self, response):
		return response
HTTPNullAuth=HTTPNullAuth() #it might as well be a singleton





@app.route('/user/<userid>')
def user(userid):
	user = None #TODO: load user based on userid. but maybe i don't care about this, actually.
	return render_template("user.html", user=user)

@app.route('/')
def index():
	return render_template("index.html", current_user=current_user)

@app.route('/logout', methods=["POST"])
def logout():
	"""
	# TODO: implement CSRF protection
	# ( this requires... WTForms? I think? )
	"""
	logout_user()
	return redirect("/")

@app.route("/login")
@app.route("/login/<provider>", methods=["GET","POST"])
def login(provider=None):
	# TODO: put the rendering *into* each provider? so we just say /login/<provider>, find the provider, and do their code?
	if provider is None:
		# TODO: sort the OAuths before the OpenIDs before User/pass before Email before Pseudoanon
		return render_template("login.html", providers=[PROVIDERS[p] for p in sorted(PROVIDERS)])
	else:
		try:
			provider_ = PROVIDERS[provider]
			assert provider == provider_.__name__.lower(), "Provider key string must match"
			provider = provider_
			del provider_
		except KeyError:
			return "Unsupported OAuth provider.", 404
		
		#
		return provider.handle() #..wait.. what if the provider needs to redirect? or has a different number of steps in their flow? or whatever? fuck
		# reallllllly what I need is to call/cc, aka yield, aka what python has, but what Flask doesn't support. hm. 
		# is difficult to use;5D
		

# as a console program, without having to worry about saving state:
# login():
# method = ask_for_login_method()
# try:
#   user = method()
#   login_user(user)
# except AuthFail: pass
# loop back up to the menu, now 


if __name__ == '__main__':
	app.debug = True
	app.secret_key = "butts"
	
	load_oauth_credentials()

	import ssl
	t = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	t.load_default_certs() # OAuth2 specs that you MUST use TLS, because for simplicity it doesn't do any crypto itself. This is probably a good idea, but it does make testing tricky.
	t.load_cert_chain("localhost.crt","localhost.key")
	app.run(use_reloader=False, host="0.0.0.0", ssl_context=t)
