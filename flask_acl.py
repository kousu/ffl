

import flask
from flask import *
from flask.ext.login import current_user

from functools import wraps




class ACL(object):
	"""
	Framework for Access Control Lists for Flask.
	Works with Flask-Login
	
	app = Flask(__name__)
	acl = ACL(app)
	
	#@acl
	
	When you set an ACL object on your app, every view defaults to private.
	To allow access, you must explicitly allow.
	"""
	def __init__(self, app):
		if not hasattr(app, 'login_manager'):
			raise ValueError("You must set a Flask-Login LoginManager on your app before using Flask-ACL")
		
		self._app = app
		#self._app.before_request(self._check_acl)
		# ---> TODO: default all apps to 
	
	def _check_acl(*args, **kwargs):
		self._app.logger.debug("_check_acl: %s, %s", args, kwargs)
		if current_user.id == "unauthed":
			return abort(401)
	
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
