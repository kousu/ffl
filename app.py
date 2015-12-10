#!/usr/bin/env python3

import os.path
import time
import base64, itsdangerous, json
import mimetypes
from flask import Flask, Response, request, redirect


import logging
logging.basicConfig(format="%(levelname)s: %(message)s")
logging.getLogger().setLevel(logging.DEBUG)


app = Flask(__name__)
#SSLify(app) #TODO: https://github.com/kennethreitz/flask-sslify forces https:// URLs; this is necessary to protect the session cookies, obviously


signer = itsdangerous.Signer("lawlcats")

# DEBUG: generate an auth token
AUTH = json.dumps({"p": "test", "t": int(time.time()) + 200})
AUTH = AUTH.encode("ascii") # is this safe ???
AUTH = signer.sign(AUTH) #TODO: use pycrypto instead of itsdangerous
AUTH = base64.b64encode(AUTH, b"-_") #use URL-safe b64
AUTH = AUTH.decode("ASCII")
print("http://localhost:5000/locked/%(AUTH)s/%(fname)s" % {'AUTH': AUTH, 'fname': "test"})

@app.route("/locked/<session>/<fname>", methods=['GET'])
def cookify(fname, session):
	"""
	Record the session token, but point the user at the 'canonical' URL for the thing
	Modern browsers interpret 301s as "erase this page from history", which is exactly the behaviour I want: I don't want people to be able
	Now, they can still use the inspector, or any number of sniffers, to find the auth token (it's also, currently, in their cookies)
	but we don't protect against malicious readers. if you suspect your friends are reposting you maliciously you (TODO: support)
	"""
	location = "/%(fname)s" % locals()
	logging.info("Setting a cookie '%s' and reloading to %s", session, location)
	
	r = redirect(location, 301)
	r.set_cookie('auth', session) #??
	return r

@app.route("/<fname>", methods=['GET'])
def guarded_get(fname):
	
	type, encoding = mimetypes.guess_type(fname) # we may edit fname, so do this first
	logging.info("Guessing %s is %s+%s" % (fname, type, encoding))
	
	# XXX sanitize ".."s somehow to avoid jumping up. can i just normpath or something?
	#fname = os.path.abspath(os.path.join(".", fname))
	logging.debug("fname = %s" % (fname,))
	if fname.endswith(".locked"):
		logging.warn("%s already ends in '.locked'. runaway redirect?", fname)
	
	try: #if anything fails, we give a 404. note: timing attacks might still be possible.
		if os.path.exists(fname+".locked"):
			# the resource is locked
			if os.path.exists(fname):
				logging.warn("Both %s and %s.locked exist.")
			
			# here's the majicks:
			#  we look for a cookie containing the auth token
			if 'auth' not in request.cookies:
				raise ValueError("No auth found")
			auth = request.cookies['auth']
			logging.info("AUTH = %s", auth)
			# now, unwrap auth
			auth = base64.b64decode(auth,b"-_")
			auth = signer.unsign(auth)
			auth = json.loads(auth.decode("ascii"))
			if not ('p' in auth and 't' in auth and isinstance(auth['p'],str) and isinstance(auth['t'],int)):
				raise ValueError("Invalid auth")
			if not (auth['p'] == fname):
				raise ValueError("Auth is for a different file: expected %s, got %s" % (fname, auth['p']))
			if not auth["t"] > time.time():
				raise ValueError("Expired auth")
			
			fname = fname + ".locked"
		else:
			assert os.path.exists(fname)
	
		return Response(open(fname), 200, mimetype=type)
	except Exception as exc:
		logging.info("failed because: %s", exc)
		return Response("<html><body><h1>404 /%s Not Found</h1></body></html>" % fname, 404)
	


if __name__ == '__main__':
	app.run(debug=__debug__)
