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
from flask.ext.login import current_user

import binascii
import shelve

class LoginLessBase(object):
	def __init__(self, app):
		self.app = app
		
		self.app.login_manager.login_view = None #if we're using login-less then we're *not* using any other login method. maybe. i don't know.
		app.route("/auth/<key>")(self._auth_view)
	
		
	def _auth_view(self, key):
		# look up key
		user = self.get_user(key)
		if user is not None:
			login_user(user)
	
	def get_user(self, key):
		"""
		
		"""
		raise NotImplementedError("Override to implement")
	
	def rekey_user(self, user):
		"""
		
		"""
		raise NotImplementedError("Override to implement")







class ShelveLoginLess(LoginLessBase):
	"DANGER: DO NOT DESERIALIZE UNTRUSTED INPUT"
	def __init__(self, app, database):
		super().__init__(app)
		self.DB = shelve.open(database)
	
	def get_user(self, key):
		# TODO: 
		return self.app.login_manager.user_loader(self.DB[key])
	
	def add_user(self, user):
		user.rekey()
		self.DB[user.key] = user.get_id()
		
		self.DB.sync()
	
	def rekey_user(self, user):
		del DB[user.key] #???? this is dumb
		add_user(user)


LoginLess = ShelveLoginLess



def make_more_secure_token(bitlength=64*8):
	"Drop-in compatible with `flask.ext.login.make_secure_token <https://flask-login.readthedocs.org/en/latest/#flask.ext.login.make_secure_token>` but with *no* correlation between the user and the token."
	"To use this you *definitely* need to store the token in your database."
	"Bitlength defaults to 512, which matches the output from make_secure_token."
	"But, you should be aware: make_secure_token() is designed so that if people change the information it invalidates the tokens, so you should be careful to rekey when people change their passwords."
	
	if bitlength % 8 != 0:
		raise ValueError("bitlength must be an even number of bytes")
	return binascii.hexlify(os.urandom(bitlength//8))

# a 'token' is *more* than a password: it's identification and authorization in one.
# this has really nice UX: if you have the token you get in without thinking about it (ssh keys are like this too)
# but it means *it must not* be sniffed, because it gives full access to the account


def RandomTokenUserMixin(UserMixin):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		if not getattr(self, 'key', None):
			self.rekey()
		
	def rekey(self):
		self.key = make_more_secure_token()
		# TODO: immediately persist this change to the database
		# problem: this is abstracted away from the database




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




# So, what *this* extension does is


#  - idea: 
# the DB should just store key -> user_id and then call user_loader on the sly
# 

def test():
	app = Flask(__name__)
	lm = LoginManager(app)
	ll = LoginLess(app, "accounts.dbm") #this is annoying, but i'll fix the API to suck less later
	
	@app.route("/")
	def index():
		return "<html><body><h1>Test App For Gigas</h1><a href=%(account)s>[Account]</a></body></html>" % {"account": url_for("account")}
	
	@app.route("/account")
	def account():
		return "<html><body><h1>Account Page</h1>Hello <em>%(id)s</em>. <br/>Your details are: %(j)s.</body></html>" % {"id": current_user.get_id(), "j": json.dumps(current_user.__dict__)}
	
	# fuck youuuuuuuuuuuuuuuu flask. in debug mode you run the werkzeug reloader which *breaks* bc it means the shelve is opened twice in one process)
	# what the hell? is your webserver not supposed to? I guess you really really really expect *only* to use a SQL backend, eh??? FUCK YOUUU
	app.run(debug=True, use_reloader=False)
	

if __name__ == '__main__':
	test()
