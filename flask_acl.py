

import flask
from flask import *
from flask import _app_ctx_stack
from flask.ext.login import current_user

from flask.helpers import _endpoint_from_view_func

from functools import wraps


# Okay so question:
# first: this thing doesn't necessarily need to come as a class, does it?
# second: should we store the permission statefully?
# third: where the arguments at?

# question:
# if the rule is "allow only if everyone says allow, and deny if any don't, and deny if the ACL is empty"
# i.e. is
# allow: A1
# deny: D1
# deny: D2
# allow: A2
# deny: D3
# allow: A3
# the same as
# allow: A1 | A2 | A3
# deny: D1 | D2 | D3
# which is the same as
# union(A1,A2,A3) \ union(D1,D2,D3)
# this has the feature that denies always override

# one design:
# each .allow / .deny call wraps the function
# so there's a nested chain of wrapped functions
# 

# two design:
# explicitly record a list of ACL predicates, the way @before_request() records a list of funcs
#  this is tricky because the predicates need to be per-endpoint, which means I need to deal with guessing the

# two is good because the code to enforce the ACLs is simpler so more safe
#  especially in that implementing .public() sanely: we could say that .public() just chains into the rest of the system, and can be overridden by a deny, but that's  .public() *erases* the previous ACL list and just sets itself
#   ==> unix perms have a special bit for "public": o+rwx. 
#   Unix perms have a subtle quirk in this:
#    -rw----r-- 1 root  wireshark 29 Dec 19 20:40 A
#   can be read by anyone (because it's o+r) EXCEPT for people in the wireshark group
#   so sw
# This is not at all appropriate for the web: on unix, theoretically at least, every account is named and given out by hand by a sysadmin.
#  but on the web you can have lots of totally anonymous users. because of the quantitative difference in degree, there's a qualitative difference between the "other" bits on unix and "public" on a website
# (this gets hazy with large institutions, like a campus or corporate network, where pam_ldap.so might let you into any account on any server where thousands of other people have files. but at least there you still can't arbitrarily make new alt accounts)
#

# but the indirection through the endpoint name is tricky (I'm not totally sure why flask felt it necessary to even have endpoint names; if they can map route -> endpoint -> function why can't they map route -> function directly and drop the intermediary?)
# one is something like: for allow()s: if they match you let the ACL through, if they don't you . for deny()s you break 
# two is 

# If the semantics were: "first match wins" then one design is simple to implement: for allows, if you match, render the view, otherwise...render the view? oh wait, no, actually wrapping is not so simple, eh?
# hmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm

# Okay, decision:
# I want the semantics to be as if:
#  current_user.get_id() in union(A for A in Allows) - union(D for D in Denies)
# Is there an efficient way to do this in the presence of predicates? and without actually constructing the access set?
# ....but actually: being able to read the list explicitly is useful for UI: you can tell if someone is in a set or not by scanning
# being clever by stacking wrappers, then, is dumb
# Why did I want predicates in the first place?
# - because I want to be able to shell out generically. and the list has to be computed per-request instead of at boot.
# How would that look?

def acl_for(user, endpoint, **kwargs):
	"return the ACL for endpoint, i.e. the set of user_ids that have access to that endpoint"
	
	# find the current app
	app = _app_ctx_stack.top.app
	
	return app.acl.check(user, endpoint, **kwargs)	

# request comes in
# we ask acl_for(user, endpoint, **args)
# the part that needs factoring is:
# so I can't nicely just say
# @allow(set
# @allow(
# @deny(
# because.. why?? why not? it seems like I should be able to do this shit ugh
# because
# so what do I do?
# @allow()
# okay, so: we parameterize on (endpoint, tuple(view_args.items())
# For views with no parameters this is just (endpoint,())
# otherwise there's something more
# it's 

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

			
