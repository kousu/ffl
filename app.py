#!/usr/bin/env python3

import os.path
import time
import base64, itsdangerous, json
import mimetypes
from flask import Flask, Response, request


import logging
logging.basicConfig(format="%(levelname)s: %(message)s")
logging.getLogger().setLevel(logging.DEBUG)


app = Flask(__name__)
signer = itsdangerous.Signer("lawlcats")
print(base64.b64encode(signer.sign(json.dumps({"p": "test", "t": int(time.time()) + 20}).encode("ascii"))))

@app.route("/<fname>/<session>", methods=['GET'])
def cookify(fname, session):
	location = "/%(fname)s" % locals()
	logging.info("Setting a cookiefff '%s' and reloading to %s", session, location)
	r = Response(status=301, headers={'Location': location})
	r.set_cookie('auth', session) #??
	return r

@app.route("/<fname>", methods=['GET'])
def guarded_get(fname):

	type, encoding = mimetypes.guess_type(fname) # we may edit fname, so do this first
	logging.info("Guessing %s is %s+%s" % (fname, type, encoding))

	# XXX sanitize ".."s?!
	#fname = os.path.abspath(os.path.join(".", fname))
	logging.debug("fname = %s" % (fname,))
	
	try: #if anything fails, we give a 404. note: timing attacks might still be possible.
		if os.path.exists(fname+".locked"):
			# the resource is locked
			if os.path.exists(fname):
				logging.warn("Both %s and %s.locked exist.")
			
			# here's the majicks:
			#  we look for a cookie
			if 'auth' not in request.cookies:
				raise ValueError("No auth found")
			auth = request.cookies['auth']
			logging.info("AUTH = %s", auth)
			# now, unwrap auth
			auth = base64.b64decode(auth)
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
