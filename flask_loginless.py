"""
    flask_loginless
    ~~~~~~~~~~~~~~~
    
    Make login smoother by giving out giving secret crypto-strong keys.
    My hope is this will enable federated identity on the web by making it easy to hand out, manage, and revoke accounts that aren't really accounts on your site.
    which is sort of similar to how `Ricochet <https://github.com/ricochet-im/ricochet>` is designed.
    (TODO: this would get along more webbily in conjunction with OAuth (see: `python-social-auth <http://psa.matiasaguirre.net/>`))
    
    Implemented as an extension to an extension: `Flask-Login <https://flask-login.readthedocs.org/>`.
    
    BEWARE:
    i.  this uses GET requests to change state. Only one, but still. In this one case this thing can suck my dick.
    ii. there's CSRF vulns in this. I am hopeful it can be made secure, but it needs review. maybe LoginManager._session_protection() does some magic.
    
    :copyright: (c) 2015 kousu
    :license: BSD, see LICENSE for more details.
"""

from flask import *
from flask.ext.login import *
from flask.ext.login import login_user, logout_user, current_user, UserMixin
from flask.ext.sslify import *

import os
from base64 import *
import binascii
import shelve

from datetime import *

import flask.ext.login

# TODO:
# - since this makes views, maybe it should be a Blueprint? What's the difference between a flask extension and a blueprint?



# a 'token' is *more* than a password: it's identification and authorization in one.
# this has really nice UX: if you have the token you get in without thinking about it (ssh keys are like this too)
# but it means *it must not* be sniffed, because it gives full access to the account

# I should just call this "token auth"
# note! lots of places use this! e.g. gitlab: https://gitlab.com/kousu/butts.atom?private_token=y2aAcB61xrC_-wKHT-16


def make_more_secure_token(bitlength=64*8):
	"Drop-in compatible with `flask.ext.login.make_secure_token <https://flask-login.readthedocs.org/en/latest/#flask.ext.login.make_secure_token>` but with *no* correlation between the user and the token."
	"To use this you *definitely* need to store the token in your database."
	"Bitlength defaults to 512, which matches the output from make_secure_token."
	"But, you should be aware: make_secure_token() is designed so that if people change the information it invalidates the tokens, so you should be careful to rekey when people change their passwords."
	
	if bitlength % 8 != 0:
		raise ValueError("bitlength must be an even number of bytes")
	
	token = os.urandom(bitlength//8) # generate token
	
	token = urlsafe_b64encode(token) #write in base64
	token = token.rstrip(b"=")
	
	#token = binascii.hexlify(token) #write as hex characters
	
	return str(token, "ascii") # write as a str, instead of bytes, because HTTP


class LoginTokenMixin(UserMixin):
	"A mixin for Flask-Login User objects which generates and remembers."
	
	@classmethod
	def reload(cls, id, token):
		C = cls(id)
		C.id = id
		C.token = token
		return C
	
	def get_auth_token(self):
		if not hasattr(self,'_token'):
			self.invalidate_token()
		return self._token
	
	def invalidate_token(self):
		"""
		Invalidate this user's authentication token by forgetting it and creating a new one.
		
		BEWARE: When you call this, make sure to immediately update any copies (e.g., in your database)
		"""
		self._token = make_more_secure_token()



class LoginLess(object):
	"""
	A Flask extension to make login less painful. Get it?
	
	Everybody hates accounts. Twitter, Facebook, Soundcloud,...
	who cares? It's the worst. People invest in making accounts
	for the sake of being able to use the services their friends
	are using. But what about small time sites, like personal blogs?
	These sites have no way to take advantage of identity,
	unless they farm out identity through Disqus.
	
	So, the idea is: instead of a username and password (or, if
	you're brave, an OAuth session token), give your users a key,
	and put that key in a link, like Google Docs and Dropbox can.
	Now, in those cases the key protects a file, whereas here
	the key protects an account, which is a litttttle dodgier.
	
	The endpoint this extension creates is "/auth/<key>?next=<url>"
	next (which is optional) gives a URL to redirect to after login.
	Make it less painful for people who come to your site to get
	their own personal keys: all it should take is one click and then a bookmark.
	Tip: in your tempaltes don't call it "logging in", call it "recognized" or "known to me".
	
	Unfortunately it's still painful on the server side. The 'less'
	is for the sake of for your users. Because Flask-Login is
	database-agnostic, so is Flask-LoginLess, and this means some work.
	It repurposes Flask-Login's User.get_auth_token() as a login key,
	so, you need to tell it how to recover an account given this key,
	like how you need to tell Flask-Login how to recover an account
	given a user ID. In fact, Flask-LoginLess calls out to your
	Flask-Login @LoginManager.token_loader, so you may already be done.
	
	If not, you will need to make it, and that almost certainly means
	modifying your database scheme as well. It *is* technically possible
	to just do something like:
	```
	@lm.token_loader
	def token_load(token):
		users = Users.query.all()
		for user in users:
			if user.get_auth_token() == token: return user
		else:
			return None
	```
	but that's going to be stupidly slow if you are at any kind of scale.
	Better is:
	```
	@lm.token_loader
	def token_load(token):
		users = Users.query.search(token=token)
		if users: return users.first()
		else:
			return None
	```
	But you will need to adapt it to your specific backend, unfortunately.
	
	Note also: using a GET link for changing state is specifically against
	the w3 guidelines, the sort of bad decision that enables CSRF attacks.
	I *think* the most that an attacker can do is a session-fixation attack,
	except with an account: they can, behind your back, log you into an
	account they made. If you don't notice and put secret information in that account,
	the attacker has it.
	So let me say this: LoginLess is explicitly intended to prove identity
	to the server, not to prove yourself to the world.
	The accounts behind LoginLess should afford any serious identity theft;
	they should probably not even contain.
	
	As soon as someone logs in they will.
	"""
	
	def __init__(self, app, only_keys = True, insecure = False):
		"""
		app should be your Flask app 
		if only_keys is set, then LoginLess is the *only* supported login method, which means everyone
		insecure can be set to disable Flask-sslify, but you shouldn't do this unless you really need to:
		 it is not safe to use LoginLess without TLS
		 it was unsafe enough to use session cookies without TLS
		 but at least session cookies *change*. the user key doesn't, unless the admin explicitly revokes it.
		 since LoginLess links are meant to be bookmarked (or more likely, saved to a feed reader)

		"""
		if not hasattr(app, 'login_manager'):
			raise ValueError("You must set a Flask-Login LoginManager on your app before using Flask-LoginLess")
		if not getattr(app.login_manager, 'token_callback', None):
			raise ValueError("You must set a Flask-Login LoginManager.token_loader on your app before using Flask-LoginLess")
		
		insecure = True #DEBUG. TODO: DISABLE THIS
		if not insecure:
			SSLify(app) #TODO: check if this sets the session cookie to Secure as well
		self.app = app
		
		if only_keys:
			self.app.login_manager.login_view = None
		app.route("/auth/<key>", endpoint="auth")(self._auth)
		app.route("/logout", endpoint="logout")(self._logout)
	
	def _auth(self, key):
		user = self.app.login_manager.token_callback(key)
		
		if user is None:
			return "No such key", 401
		if current_user != user:
			return "You are already logged in", 401
		
		login_user(user)
		# TODO: we should check that the next URL is on the same site
		#  deny it if not (i don't have any attacks in mind per se, but there's probably a way being able to next= your way out to any site will help phishing)
		return redirect(request.args.get("next", "/"))
	
	def _logout(self):
		#XXX this is vulnerable to CSRF!
		# There is this session-pinning-style attack, except it is actually an account pin:
		# Attack: someone injects a webpage which contacts http://blog.you/logout (e.g. via XMLHttpRequest, via <img src>, <script src>, lots of things...
		# then they do the same to make you hit http://blog.you/auth/<attacker_key>, now you are logged in as them.
		#
		# Mitigations: make this function check a CSRF token before working?
		#  problem: the attack is also good if you catch people when they're not logged in(which, tbh, is most people?)
		#           and then if they ever do go over to the blog, they are logged in as the attacker
		""" for reference: here's how github protects against logout CSRF: a random 512-bit token.
                    also, apparently the form is independently nonced, which must be a separate subsystem that they haven't noticed
<form accept-charset="UTF-8" action="/logout" class="logout-form" data-form-nonce="51dc6629e39b3b022b7725ae086a56885fe28895" method="post">
<input name="authenticity_token" value="FcEVNkM7ZR8mLU1FjJAoANAbFAwZFbgB9PtfjABxTB8sUK4QbUUw1UrXrltER6X1ClfSx81x0dlWAXNwRKAFng==" type="hidden">
            <button class="dropdown-item dropdown-signout" data-ga-click="Header, sign out, icon:logout">
              Sign out
            </button>
</form>
		with suitable CSS (as they have) it doesn't /look/ like a POST link, but it is
		"""
		logout_user()
		return redirect("/")
	
	def url_for(self, user):
		"generate the login-link for the given user"
		# TODO: should this check that the user actually has a valid login?
		if hasattr(user, 'get_auth_token'): #AnonymousUserMixin doesn't define this, and s
			token = user.get_auth_token()
			if token is not None: # this is just to be defensive (in case AnonymouseUserMixin ever learns not to be broken)
				return url_for("_auth", key=token) #aah, this is weird: url_for is a magic global that access other thread-local magic globals. hmm. Flask is sketchy.
		
		# users with no login can just be sent to the index, I guess
		return "/"









# Flask-Login's way of figuring out who you are:
# It first looks at the session cookie, which is signed with the server's key
#  If that contains 'user_id', is assumes that's you and calls user_loader
# Then it looks for the remember_token cookie
#  If you have set @login_manager.token_loader, then it assumes the content is a token
#  otherwise it assumes the content is a user id and calls @login_manager.user_loader,
# *failing that* it looks at the request (@login_manager.request_loader) itself
# or the HTTP "Authorization:" header (@login_manager.header_loader) (the latter is generalized by the former)
#
# All of these are expected to *produce a user object*, not a user ID
# takes a user ID and produces a user object
# The upshot is: if you set a token_loader then you use tokens, unless you use, unless you have for some godawful reason chosen to use HTTP Digest Auth (which is BROKEN because MD5 is broken)
# Flask-login is not /great/ here and even less documented. I had to work this shit
#TODO: it would be a lotttt simpler if the flow was just:
# and also if instead of having four callbacks that it has to negotiate each request, just have one which is tagged, so @lm.loader('user_id')


class UserDB(shelve.Shelf):
	"""
	Wraps a shelve.Shelf to make it work like a cheap doubly-indexed database for use with the User class
	It is keyed on user id, but it also maintains an index { login key: user id }
	because while we want id to be the primary key for most situations,  we also want to support auth without sending the ID too (for elegance reasons)
	This is really just a hack in place of setting up an entire SQL table with (id primary key, token unique, index(token))
	
	TODO: make this a wrapper around a wrapper:
	     a TokenIndex which soley, and it should register changes
	         ah, but registering changes is a bitch
	"""
	def __init__(self, file):
		self._db = shelve.open(file)
		self._key_idx = {self._db[id].get_auth_token(): id for id in self._db}
	def __getitem__(self, id=None, token=None):
		"k can either be .get_id() or .get_auth_token()"
		if token in self._key_idx:
			# translate auth_token -> ids, if necessary
			id = self._key_idx[token]
		# now, assume t is a .get_id()
		return self._db[id]
	
	def __setitem__(self, id, user):
		if id != user.get_id(): raise ValueError("mismatched id fields")
		t = user.get_auth_token()
		
		# make sure we don't add dupes by accident
		# we can't have dupe ids of course, but we might miss dupe tokens
		if t in self._key_idx:
			if id != self._key_idx[t]:
				raise ValueError("Duplicate auth tokens. New user %(new)s and old user %(old)s share token %(t)s" % {"old": self._key_idx[k], "new": id, "t": t})
		
		# XXX what happens if the user is rekeyed? this is unlikely, but a rekeying followed by a key collision with the discarded key will appear to be dupe, even though it's not
		
		self._db[id] = user
		self._key_idx[t] = id
	
	def __delitem__(self, id):
		del self._key_idx[self._db[id].get_auth_token()]
		del self._db[id]
	
	def __getattr__(self, attr):
		"pass other methods through to self._db"
		return getattr(self._db, attr)


def test():
	app = Flask(__name__)
	#app.secret_key = os.urandom(52) #<-- a side-effect of changing the secret key at boot is that all sessions are invalidated
	app.secret_key = "LoginLess"
	
	users = UserDB("accounts.dbm")
	
	lm = LoginManager(app)
	@lm.user_loader
	def user_load(id):
		try:
			return users[id]
		except KeyError:
			return None
	
	@lm.token_loader
	def token_load(token):
		try:
			return users._key_idx[token] #TODO: clean
		except KeyError:
			return None
	
	ll = LoginLess(app)
	
	#@app.before_request
	#def q(): #DEBUG
	#	print("users =", pformat(dict(users)), pformat(users._key_idx))
	
	@app.route("/")
	def index():
		return ("<html><body><h1>LoginLess Test App</h1> "
                        "<a href=%(newaccount)s>[New Account]</a> "
                        "<a href=%(account)s>[Account]</a> "
                        "</body></html>") % {x: url_for(x) for x in ["newaccount","account"]}
	
	@app.route("/newaccount", methods=["GET", "POST"])
	def newaccount():
		if request.method == "GET":
			return ("<html><body><h1>New Account</h1> "
                        "<form action=%(this)s method=POST><input autofocus type=text name='identity' placeholder='Tell me who you are, child.'><input type=submit style='display: none'></form>"
                        "</body></html>") % {"id": current_user.get_id(), "j": json.dumps(current_user.__dict__), "this": url_for("newaccount")}
		if request.method == "POST":
			# make a new user
			if request.form['identity'] in users:
				# XXX should this give a different HTTP error ? It should be a 4xx code, but nothing seems appropriate.
				return "<html><body><h1>Account taken</h1><em>%(id)s</em> already taken.</body></html>" % {"id": request.form['identity']}
			user = TokenUserMixin(request.form['identity'])
			users[user.get_id()] = user
			login_user(user)
			#assert current_user is user #this is actually False: logging in causes the user to be *reloaded* (as in, from whatever lm.user_loader says to do)
			return redirect(url_for("account"))
	
	@app.route("/account")
	def account():
		return ("<html><body><h1>Account Page</h1> "
                        "Hello <em>%(id)s</em>. "
                        "<br/>Your details are: %(j)s. "
                        "<br/>Your login link is <a href=%(auth)s>%(auth)s</a>. "
                        "</body></html>") % {"id": current_user.get_id(), "j": json.dumps(current_user.__dict__),
                                             "auth": ll.url_for(current_user)}
	
	# fuck youuuuuuuuuuuuuuuu flask. in debug mode you run the werkzeug reloader which *breaks* bc it means the shelve is opened twice in one process)
	# what the hell? is your webserver not supposed to? I guess you really really really expect *only* to use a SQL backend, eh??? FUCK YOUUU
	app.run(debug=True, use_reloader=False)
	

if __name__ == '__main__':
	test()
