

import flask
from flask import *
from flask.ext.login import current_user

from functools import wraps


# Okay so question:
# first: this thing doesn't necessarily need to come as a class, does it?
# second: should we store the permission statefully?
# third: where the arguments at?

class ACL(object):
	"""
	Framework for Access Control Lists for Flask.
	# XXX maybe this should be called "Permissions"?
	Works with Flask-Login
	
	app = Flask(__name__)
	acl = ACL(app)
	
	#@acl
	# For now, reading and writing permissions are not distinguished, to keep the implementation simple.
	#  if you want to have a single page that has different permissions for readers and writers
	# you should split it into two methods with different methods:
	@app.route("/account", methods=["GET"])
	@acl(...readers...)
	def read_account(....): ...
	
	@app.route("/account", methods=["POST"])
	@acl(...writers...)
	def write_account(....): ...
	
	To get the full benefit of this system, you should rearrange your app so that each distinct action is isolated to a single route
	and then ACL them all separately
	so that each route can be, e.g. /manage/<user>
	
	When you set an ACL object on your app, every view defaults
	to private (i.e. permissions fail closed). You must explicitly
	mark every view with an ACL rule, even if it's just @ACL.public
	"""
	def __init__(self, app):
		if not hasattr(app, 'login_manager'):
			raise ValueError("You must set a Flask-Login LoginManager on your app before using Flask-ACL")
		
		self._app = app
		self._app.before_request(self._check_acl)
		# ---> TODO: default all apps to 
	
	def _check_acl(self, *args, **kwargs):
		self._app.logger.debug("_check_acl: %s, %s", request.method, request.path)
		self._app.logger.debug("_check_acl: args=%s, kwargs=%s", args, kwargs)
		self._app.logger.debug("_check_acl: endpoint: %s, viewargs = %s", request.url_rule.endpoint, request.view_args)
		# Do I need to attach
		
		# I want to hook 
		#return abort(401)
	
	def private(self, view):
		"Make the given view totally public. i.e. skip ACL checking and just deny"
		@wraps(view)
		def decorated_view(*args, **kwargs):
			return abort(401)
		return decorated_view
	
	def public(self, view):
		"Make the given view totally public. i.e. disable ACL checking"
		@wraps(view)
		def decorated_view(*args, **kwargs):
			return view(*args, **kwargs)
		return decorated_view
			
	def __call__(self, predicate):
		"""
		Decorate view `func` to set the ACL callbacks"
		
		This is to be used like:
		  @app.route("/view/<arg>")
		  @acl(lambda user, arg)
		  def view(arg): ....
		""" 
		def decorator(view):
			@wraps(view)
			def decorated_view(*args, **kwargs):
				if predicate(current_user, *args, **kwargs) == True:
					return view(*args, **kwargs)
				else:
					return abort(401)
			return decorated_view
		return decorator
