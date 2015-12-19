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

import os
import binascii
import shelve

class LoginLess(object):
	def __init__(self, app):
		self.app = app
		
		self.app.login_manager.login_view = None #if we're using login-less then we're *not* using any other login method. maybe. i don't know.
		app.route("/auth/<key>")(self._auth)
		print(self._auth.__name__)
	
		
	def _auth(self, key):
		# look up key
		user = self.app.login_manager.token_callback(key)
		if user is not None:
			login_user(user)
	





def make_more_secure_token(bitlength=64*8):
	"Drop-in compatible with `flask.ext.login.make_secure_token <https://flask-login.readthedocs.org/en/latest/#flask.ext.login.make_secure_token>` but with *no* correlation between the user and the token."
	"To use this you *definitely* need to store the token in your database."
	"Bitlength defaults to 512, which matches the output from make_secure_token."
	"But, you should be aware: make_secure_token() is designed so that if people change the information it invalidates the tokens, so you should be careful to rekey when people change their passwords."
	
	if bitlength % 8 != 0:
		raise ValueError("bitlength must be an even number of bytes")
	return binascii.hexlify(os.urandom(bitlength//8)).decode("ascii")

# a 'token' is *more* than a password: it's identification and authorization in one.
# this has really nice UX: if you have the token you get in without thinking about it (ssh keys are like this too)
# but it means *it must not* be sniffed, because it gives full access to the account


class TokenUserMixin(UserMixin):
	def __init__(self, id, token=None, *args, **kwargs):
		self.id = id #argh
		if token is None:
			token = make_more_secure_token()
		self.token = token
		super().__init__(*args, **kwargs)
	
	def get_auth_token(self):
		""
		print("AUTH TOKEN from (%s,%s) BEING GOTTEN" % (self.get_id(), self.token))
		return self.token



# Flask-Login's way of figuring out who you are:
# It first looks at cookies
#  which looks at @login_manager.token_loader
#  then @login_manager.user_loader,
# Then it looks at the request (@login_manager.request_loader) itself
# Then at the HTTP "Authorization:" header (@login_manager.header_loader) -- which is deprecated in favour of the generalized request object method now
#
# All of these are expected to *produce a user object*, not a user ID, but
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
	 TODO: a SQL table with a proper pair of indecies would also work
	TODO: make this a wrapper around a wrapper:
		- this should be a TokenIndex, and it should register changes
	         ah, but registering changes is a bitch
	"""
	def __init__(self, file):
		self._db = shelve.open(file)
		self._key_idx = {self._db[id].get_auth_token(): id for id in self._db}
	def __getitem__(self, k):
		"k can either be .get_id() or .get_auth_token()"
		if k in self._key_idx:
			# translate .key -> .id, if necessary
			k = self._key_idx[k]
		# now, assume k is a .id
		return self._db[k]
	def __setitem__(self, id, user):
		if id != user.get_id(): raise ValueError("mismatched id fields")
		self._db[id] = user
		self._key_idx[user.get_auth_token()] = id
	def __delitem__(self, id):
		del self._key_idx[self._db[id].get_auth_token()]
		del self._db[id]
	
	def __getattr__(self, attr):
		"pass other methods through to self._db"
		return getattr(self._db, attr)


# 

def test():
	app = Flask(__name__)
	app.secret_key = os.urandom(52)
	lm = LoginManager(app)
	
	DB = UserDB("accounts.dbm")
	DB.clear() #DEBUG
	
	@lm.user_loader
	def user_load(id):
		print("Loading user %s" % (id,))
		return DB[id]
	
	@lm.token_loader
	def token_load(k):
		id = DB._key_idx[k]
		# now look up ID in the database...
		u = user_load(id)
		assert u.get_auth_token() == k
		return u
		
	ll = LoginLess(app)
	# idea: LoginLess sets app.login_manager.token_loader, switching the view to using tokens
	# and internally caches the tokens
	
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
			app.logger.info("POSTING: %s" % (request.form['identity'],))
			# make a new user
			user = TokenUserMixin(request.form['identity'])
			print("After creation:", user.__dict__)
			DB[user.get_id()] = user
			login_user(user)
			#assert current_user is user #this is actually False: logging in causes the user to be *reloaded* (as in, from whatever lm.user_loader says to do)
			return redirect(url_for("account"))
			
	@app.route("/account")
	def account():
		print("Account(): current_user=", current_user.__dict__)
		return ("<html><body><h1>Account Page</h1> "
                        "Hello <em>%(id)s</em>. "
                        "<br/>Your details are: %(j)s. "
                        "<br/>Your login link is <a href=%(auth)s>%(auth)s</a>. "
                        "</body></html>") % {"id": current_user.get_id(), "j": json.dumps(current_user.__dict__),
                                             "auth": url_for("_auth", key=current_user.get_auth_token())}
	
	# fuck youuuuuuuuuuuuuuuu flask. in debug mode you run the werkzeug reloader which *breaks* bc it means the shelve is opened twice in one process)
	# what the hell? is your webserver not supposed to? I guess you really really really expect *only* to use a SQL backend, eh??? FUCK YOUUU
	app.run(debug=True, use_reloader=False)
	

if __name__ == '__main__':
	test()
