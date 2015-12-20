#!/usr/bin/env python3
"""

"""

TODO:
# [ ] turn on SSL
#   [ ] i.e. SSLify) (this is sort of tricky to do in a test setup)
#   [ ] make sure to turn on secure cookies (which instructs browsers not to send them unless using HTTPS)
# [ ] 


# sign up methods:
# when you sign up you are given a login link and an RSS feed (which itself redirects through the login links). THE LINK IS YOUR PASSWORD.
# i. enter a pseudoanon name
# ii. enter an email. you get sent 
# iii. OAuth
# iv. OpenID
# note: in principle, python-social-auth handles all of these
#       the difference in my design is that you only use the auth method once
#       or maybe, if you lose the login link, you can use the auth method again and get given the same link again??


import os.path
import time
import base64, itsdangerous, json
import mimetypes
from flask import Flask, Response, request, redirect, session


app = Flask(__name__)
#SSLify(app) #TODO: https://github.com/kennethreitz/flask-sslify forces https:// URLs; this is necessary to protect the session cookies, obviously


app.secret_key = os.urandom(24) # set the key used for signing cookies
app.secret_key = b"butts"
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

	
# oh INTERESTING
#  hm
#  so, unlike PHP sessions, a Flask session literally jsonifies the session dictionary, base64s it, then signs it (careful: it MACs it, it's not a digital signature, because there's no public key)
#   in other words, it's already doing exactly what I planned to do
#   it even appears to be using itsdangerous, though
@app.route("/first")
def first():
	if 'first' not in session:
		session['first'] = "visited"
	else:
		assert not session.modified

	return "First: session=%s; key=%s  <a href=/second>next</a>"  % (dict(session),app.secret_key)

@app.route("/second")
def second():
	if 'second' not in session:
		session['second'] = "visited"
	else:
		assert not session.modified

	return "second: session=%s;  <a href=/third>next</a>"  % (dict(session),)

@app.route("/third")
def third():
	if 'third' not in session:
		session['third'] = "visited"
	else:
		assert not session.modified
	return "third: session=%s" % (dict(session),)


#   nit pick: I would like an auth to time out after a fixed period after the user initially uses the auth
#       this is for *my* protection, not my users (whereas generally a session expiry is to make sure people don't leave what are essentially long-lived passwords around)
#     but 
#     the cookies Flask sets are session cookies (i.e. have no expiry) but they also have a timestamp on them
#      app.permanent_session_lifetime gives how long cookies should last in browser if you set app.permanent = True
#      but! the default session manager thing (`SecureCookieSessionInterface`) checks app.permanent_session_lifetime regardless, and it will wipe the session fresh if 
#    ways you can keep a session active indefinitely, with the flask setup:
#    - if the app doesn't have permanent_session_lifetime set:
#    -   you just keep the browser open and hold onto the cookie
#    -   you could copy the cookie and manually restore it into your cookies.txt (surf and other old-netscape style) or your cookie manager (Firefox, Chrome))
#    - if it does (or, actually, even if it doesn't) you can:
#    -   refresh the page constantly
#    in unreleased flask, if you set PERMANENT_SESSION_LIFETIME to something and SESSION_REFRESH_EACH_REQUEST = False, then these attacks won't work, but
#    -   you can do something in the webapp to cause it to modify the cookie, and do that in a loop
#          in my particular application, where i'm planning on only having one thing in my app4

# ugh, maybe the capabilities design is dumb afterall
# 

# nit: a tampered signature gets your session erased TODO TEST THIS
#   I guess this is fair; the session could be invalid either due to tampering OR due to a timeout; in a timeout, you definitely want to wipe; in tampering, presumably the tamperer knew what 
#    Oh! not necessarily; there's a small DoS risk: if you can MITM someone you can tamper with their cookie and even though you can't change the data in it you can cause flask to wipe it

# TODO: since the flask session object is a dictionary, it would be more in harmony with the HTTP spec if *each entry* became a cookie
# true, this means doing more signatures and modification/deletion being a lot more finicky
#  but it also greatly reduces the risk of overflow (because some implementations truncate cookies)
# and does it send more or less data? probably more, because even the base64 of a few json-braces is not going to outweigh all the "HttpOnly" and "Path=/" strings


# weird: why is reloading the page setting a new cookie? the session isn't modified...
#   oh wait, it totally is; the hook must be on __setitem__, not by diffing the result after the fact
#   so even though the same cookie comes out, flask doesn't know that and it resigns it *updating the timestamp in the process*
#   and i guess this makes sense; just remember the rule that everytime you use '=' you are tripping it
#  oh, but actually it just always sets the cookie. always. the code that checks .modified is only to
# oh good! in bleeding edge code they've added a nod to that maybe you don't WANT to be reserializing the damn cookie each time
# https://github.com/mitsuhiko/flask/blob/d526932a09557be4aff6d27261cabb7c5c5ebb8d/flask/sessions.py#L346
# basically: set SESSION_REFRESH_EACH_REQUEST to False to disable


app.permanent_session_lifetime = 10 #seconds

if __name__ == '__main__':
	app.run(debug=__debug__)
