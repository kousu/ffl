#!/usr/bin/env python3

import os.path
import time
import base64, itsdangerous, json
import mimetypes
from flask import Flask, Response, request, redirect


app = Flask(__name__)
#SSLify(app) #TODO: https://github.com/kennethreitz/flask-sslify forces https:// URLs; this is necessary to protect the session cookies, obviously


app.secret_key = os.urandom(24) # set the key used for signing cookies
signer = itsdangerous.Signer(app.secret_key) #XXX is it a bad idea to reuse the secret here? flask just uses



def gen_token(path, timeout):
	global signer
	
	AUTH = json.dumps({"p": path, "t": int(time.time() + timeout)})
	AUTH = AUTH.encode("ascii") # is this safe ???
	AUTH = signer.sign(AUTH) #TODO: use pycrypto instead of itsdangerous
	AUTH = base64.b64encode(AUTH, b"-_") #use URL-safe b64
	AUTH = AUTH.decode("ASCII")
	return AUTH

def check_token(token, path):
	global signer
	
	# now, unwrap auth
	auth = token
	auth = base64.b64decode(auth,b"-_") #note: base64.decode can tolerate str or bytes, but encode demands bytes
	auth = signer.unsign(auth)
	auth = json.loads(auth.decode("ascii"))
	if not ('p' in auth and 't' in auth and isinstance(auth['p'],str) and isinstance(auth['t'],int)):
		raise TypeError("Invalid auth")
	if not (auth['p'] == path):
		raise ValueError("Mismatched path")
	if not (auth["t"] > time.time()):
		raise ValueError("Expired token")
	
	return True

# DEBUG: generate an auth token for the locked files
LOCKED = ["test","a/b/c/e"] #TODO: find this with os.path.walk(), or maybe os.popen("find").readlines()
for path in LOCKED:
	AUTH = gen_token(path, 20)
	print("http://localhost:5000/locked/%(AUTH)s/%(fname)s" % {'AUTH': AUTH, 'fname': path})


#TODO:
# - setting a cookie is a dumb way to pass exactly one bit of info because different pages will collide
#   the same happens if we store something in Session (which
# maybe...look at Referer?

@app.route("/auth/<path:fname>")
def authgen(fname):
	"""
	Generate new auth tokens upon request
	(in a real app, this should be done only after proving someone has authorization to know this, e.g. via them logging in and checking ACLs, or by putting this into a private)
	"""
	app.logger.debug("/authgen")
	timeout = int(request.args.get("timeout", 200))
	return "<html><body><h1>Valet Key for /%(fname)s</h1><a href='/%(token)s/%(fname)s'>/%(token)s/%(fname)s</a></body></html>" % {"fname": fname, "token": gen_token(fname, timeout)}, 200


@app.route("/<session>/<path:fname>")
def cookify(fname, session):
	"""
	Record the session token, but point the user at the 'canonical' URL for the thing
	Modern browsers interpret 301s as "erase this page from history", which is exactly the behaviour I want: I don't want people to be able
	Now, they can still use the inspector, or any number of sniffers, to find the auth token (it's also, currently, in their cookies)
	but we don't protect against malicious readers. if you suspect your friends are reposting you maliciously you (TODO: support)
	"""
	app.logger.debug("/key")
	location = "/%(fname)s" % locals()
	app.logger.info("Setting a cookie '%s' and reloading to %s", session, location)
	
	r = redirect(location, 301)
	r.set_cookie('auth', session) #??
	return r

#TODO: it would be more elegant if the token was shorter:
# instead of a json string, just send the timestamp and an HMAC.
# the HMAC is over (fname, ((here we could still use json, actually)

@app.route("/<path:fname>") #NOTE: this must be the last route added, since it behaves like a catch-all
def guarded_get(fname):
	app.logger.debug("/MAIN")
	if fname.endswith(".locked"):
		app.logger.warn("%s already ends in '.locked'. runaway redirect?", fname)
	
	type, encoding = mimetypes.guess_type(fname) # we may edit fname, so do this first
	app.logger.info("Guessing %s is %s+%s" % (fname, type, encoding))
	
	# sanitize ".."s (and tidy other weirdnesses) to avoid escaping from .
	# we exploit the fact that .. bottoms out at "/": , "/../" = "/"
	# we make the path absolute, normalize it (which means any ..s that would have escaped past the root get erased)
	# and then make it non-absolute again
	fname = os.path.normpath("/"+fname)[1:]
	app.logger.debug("fname = %s" % (fname,))
	
	if os.path.exists(fname+".locked"):
		# the resource is locked
		if os.path.exists(fname):
			app.logger.warn("Both %s and %s.locked exist.")
		
		# here's the majicks:
		#  we look for a cookie containing the auth token
		if 'auth' not in request.cookies:
			raise ValueError("No auth found")
		auth = request.cookies['auth']
		app.logger.info("AUTH = %s", auth)
		try:
			check_token(auth, fname)
		except Exception as exc:
			# if this goes wrong we give the same error message
			# this is to mitigate oracle attacks
			# note: timing oracles might still be possible.
			return "<html><body><h1>403 /%s Not Permitted</h1>%s</body></html>" % (fname, exc), 404
		fname = fname + ".locked"
	elif os.path.exists(fname):
		pass
	else:
		return "<html><body><h1>404 /%s Not Found</h1></body></html>" % fname, 404

	return Response(open(fname), 200, mimetype=type)

	

	

if __name__ == '__main__':
	app.run(debug=__debug__)
