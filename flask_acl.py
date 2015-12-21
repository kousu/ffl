"""


The fastest way to explain the semantics of this are that it's equivalent to:
 user in union(*allowed) - union(*denied)
where allowed is a set of groups of allowed people, for the current view
  and denied  is a set of groups of denied people,  for the current view
The main properties of this choice are:
 * default deny: without explicit allow statements, the allow set is empty so the overall set is empty and the view is totally blocked.
 * deny always wins: no matter how many times a user is allowed, if they are denied in a single group then they are denied totally

Also, the "current view" is actually the combination (endpoint, view_args):
for views with no args, this is essentially just the endpoint itself,
but for others the. This is so that the ACLs can change depending on which particular subpage (e.g. which user is viewing which other users' page).


Similar:
* https://pythonhosted.org/Flask-Security/features.html
  --> this does indeed make a Blueprint: https://github.com/mattupstate/flask-security/blob/9583dc3e63af452eb3e23c919a4697554b168330/flask_security/views.py

Flask-ACL is in direct competition with https://pythonhosted.org/Flask-Principal/. It has a more minimalist approach.
Roles and Permissions are a nice academic game, and totally floundering in the real world.
Flask-ACL does not define what a permission is or define a way to ask if it is acceptable; rather, it says that every
activity is an HTTP request, and if you need to guard particular activities in different ways, you should split them into separate views and guard those.


TODO:
- [ ] Sometimes it's a nuisance that Flask-ACL eats perms on everything by default.
      Just loading it breaks /static, for example. I've patched that specific case in here
      but endpoints from other modules/blueprints, like LoginLess's /auth, are also blocked
      and currently the only way around this is for the user to explicitly.
- [ ] 
"""


import flask
from flask import *
from flask import _app_ctx_stack
from flask.ext.login import current_user

from flask.helpers import _endpoint_from_view_func

from functools import wraps




class public_set(set):
	"this represents the infinite, universal, set"
	def __init__(self): pass #disable the constructor
	def __contains__(self, x): return True
	def __str__(self): return "public"
	def __len__(self): return float("inf")
	def __iter__(self): raise NotImplementedError
	def union(self, other): return self #everything joins the universal set!
public_set = public_set()
no1 = set()



# This *should* be safe from TOCTOU attacks because it's server-side:
# per request, current_user gets set once by Flask-Login, and doesn't change after that.

# figure out perms?

class ACL(object):
	"""
	Framework for Access Control Lists for Flask.
	# XXX maybe this should be called "Permissions"?
	This works with Flask-Login. User IDs (i.e. current_user.get_id()) are
	checked against the ACL on each endpoint.
	ACLs can be given as sets (or anything which can handle .__contains__(user_id)) or predicates (`lambda user_id: True | False`)
	
	Usage:
	```
	app = Flask(__name__)
	acl = ACL(app)
	```
	To get the full benefit of this system, you should rearrange your app so that each distinct action is isolated to a single route
	and then ACL them all separately
	so that each route can be, e.g. /manage/<user>
	if you find yourself checking current_user.get_id() in your code for any reas

	#@acl
	# Reading and writing permissions are not distinguished, to keep the implementation simple. (this might be revisited and changed some day)
	# So, if you want to have a single page that has different permissions for readers and writers
	# you should split it into to views with different methods:
	```
	@app.route("/account", methods=["GET"])
	@acl.allow(readers)
	def read_account(): ...
	
	@app.route("/account", methods=["POST"])
	@acl.allow(writers)
	def write_account(): ...
	```
	
	When you set an ACL object on your app, every view defaults
	to private (i.e. permissions fail closed). You must explicitly
	mark every view with an ACL rule, even if it's just @ACL.public
	"""
	
	# magic constants
	ALLOW = "allow"
	DENY = "deny"
	
	def __init__(self, app):
		if not hasattr(app, 'login_manager'):
			raise ValueError("You must set a Flask-Login LoginManager on your app before using Flask-ACL")
		
		self._app = app
		app.acl = self #HMMMMMMMM
		self._app.before_request(self._enforce)
		# ---> TODO: default all apps to 
		self._rules = {} #indexed by endpoint name
		
		self.public("static")
	
	def check(self, user, endpoint, **kwargs):
		try:
			v = self._rules[endpoint]
			allows = v.get('allow',[])
			denies = v.get('deny',[])
		except KeyError as exc:
			self._app.logger.debug("Bugger: %s", exc)
			allows = denies = []
	
		# this computes allows - denies, but in a lazy way,
		# so instead it computes "user in allows - denies"
		
		self._app.logger.debug("ACL.check(%s, %s, %s): allows=%s, denies=%s", user.get_id(), endpoint, kwargs, allows, denies)
		
		return any(p(user, **kwargs) for p in allows) and not any(p(user, **kwargs) for p in denies)

	
	def _enforce(self, *args, **kwargs):
		if not request.url_rule: return #apparently, before_requests are called even if there is no route found
		
		self._app.logger.debug("_check_acl: user: %s", current_user.get_id())
		self._app.logger.debug("_check_acl: %s, %s", request.method, request.path)
		self._app.logger.debug("_check_acl: args=%s, kwargs=%s", args, kwargs)
		self._app.logger.debug("_check_acl: endpoint: %s, viewargs = %s", request.url_rule.endpoint, request.view_args)

		# Do I need to attach
		if not self.check(current_user, request.url_rule.endpoint, **request.view_args):
			# XXX is hardcoding a 401 a good idea? SEO-friendly URLs give away the content of a post, and maybe that is sensitive
			return abort(401)
		
	def add(self, endpoint, type, users):
		"""
		Users can either be a callable lambda user, **view_args -> bool
		or a sequence of user ids (as in, user.get_id())
		"""
		if type not in [self.ALLOW, self.DENY]:
			raise ValueError("Invalid ACL rule type.")
				
		if not callable(users):
			# assume users is a set-like thing, and wrap it to be a callable that 'generates' it, so that we don't need to special-case this later in _check_acl
			if not hasattr(users, '__iter__'):
				raise TypeError("Users must be either a sequence or a callable to generate that sequence at request-time.")
			_users_set = users
			users = lambda user, *args, **kwargs: user.get_id() in _users_set
		
		self._app.logger.info("Adding rule [%s][%s] = %s", endpoint, type, users)
		self._rules.setdefault(endpoint, {})
		self._rules[endpoint].setdefault(type, [])
		self._rules[endpoint][type].append(users)
	
	
		
			
	## Public API: decorators
	
	# TODO: factor these. a factory function?
	
	def allow(self, users, endpoint=None):
		if endpoint is not None:
			self.add(endpoint, self.ALLOW, users)
		else:
			def decorator(view):
				self.add(endpoint if endpoint is not None else _endpoint_from_view_func(view),
				         self.ALLOW,
				         users)
				return view
			return decorator
	
	def deny(self, users, endpoint=None):
		if endpoint is not None:
			self.add(endpoint, self.DENY, users)
		else:
			def decorator(view):
				self.add(endpoint if endpoint is not None else _endpoint_from_view_func(view),
				         self.DENY,
				         users)
				return view
			return decorator
	
	def public(self, endpoint=None):
		return self.allow(public_set, endpoint=endpoint)

			
def acl_for(user, endpoint, **kwargs):
	"return the ACL for endpoint, i.e. the set of user_ids that have access to that endpoint"
	
	# find the current app
	app = _app_ctx_stack.top.app
	
	return app.acl.check(user, endpoint, **kwargs)
