#!/usr/bin/env python3
"""
Thingy of thing
"""


# Key point: your magic login link is ONLY given once
#  to get it again, you must RESET it, invalidating the old one
#  you are given it:
#   - on the page immediately after account creation
#   - if you go to that page explicitly
#   (otherwise you will need)

import os.path
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
import mimetypes
from flask import Flask, Response, request, redirect, session
from flask.ext.login import login_user, logout_user, current_user, UserMixin, LoginManager

import shelve
import uuid

"""
Flask-login has a 'login_required' deocrator that you can use to tag pages ("Views") as needing a valid user. But it is not smarter than that. In particular, it *could* be a great place to check ACLs
so I think the first thing I need to do is replace login_required with acl_required that checks ACLs
 in the vein of flask-login, what happens is:
  go to /protected.html
    check current_user is not None and current_user.is_authenticated():
       -> load the page
  else:
    redirect(url_for("login", next="/protected.html"))
    #---- in Flask, the code flow has to break here to wait for the request to come around again, but in a call/cc supporting library we'd just yield here and wait to see the result
    if <user supplied credentials>:
      current_user.is_authenticated = True
      next = query.get("next") or "/index" # and then you go back and repeat, following the other path
    else:
      next = "/index"
    redirect(next)




but instead what I want is:
  go to /maybeprotected.html
   if check_acl():
     render
   else:
     error (technically this should be a 403, but we actually give 404 because URLs give useful information and someone could, in theory, brute-force your post titles; unless we embedded a long random post ID as well)




and the working login methods are:
- make a new account (but then you're "anonymous"? maybe?)
- go through the auth method you used to make a new account again
 - so, there's no way with "username" auth to do this
 - with email, you get sent basically a password reset link, and if you get it when you click it you get given

ah, for version 1:
 - the only way to login is the magic login links
 - the only way to get an account is username auth
 - two RSS links: "Subscribe" (or "Follow"?) and "Friend"
1.1:
 - email auth
1.4:
 - switch to python-social-auth and get twitter/facebook/email/username all in one system
2:
 - you can redo the auth to get logged in
   (so, e.g. receiving an unencrypted email is enough; but the 
2.1:
 - when you redo auth, there's a button to get a new link
   - or, i guess, it's as simple as " (ONLY ONE LINK AT A TIME, PLZ)
 - w

def check_acl(page, user):
	if page is world readable: return True
	else:
	   if user is None: return False # *unless* the page is specifically world readable, it is readable by no one
	   assert None not in viewers(page)
	   if user in viewers(page):

# or maybe:
# if current_user is None or current_user.is_anonymous():
#    return page is world readable #anon users can only read pages
# else:
#    # logged in users can read world readable pages, and any pages they have rights to

def viewers(page):
	"""
	sketch of the logic needed to translate
	+Friends +Family -Mom -Annamaria +Pets -Alice -Work
	into a set containing user IDs
	the main point is: minuses ALWAYS override pluses. If you explicitly minus a
	 ..oh wait, but what if you minus a whole group
	 ..well, maybe in that case, you should not be using this in the first place?
	 if someone is Family and Work and you say +Family -Work what should happen?
	  bah, well, whatever, we can deal with this in the UX phase
	"""
	viewerset = read_from_db(page)
	viewers = {}
	viewerset.sortby("+","-")
	# sort into adds and subtracts
	U, D = [{set([v[1:]]) if looks_like_userID(v[1:]) else read_from_db(v[1:]) for v in viewerset if v[0] == kind} for kind in ("+","-")]
	for users in U:
		viewers += users
	for users in D:
		viewers -= users
	return viewers

# ^ the above logic is correct (i hope) but probably slow
#   *careful* (!!! BE CAREFUL) caching can speed it up, if it becomes a problem


now, my RSS feed works a little differently:
 it

@logins.login_required


# spec:
# - I want people who sign up via email to have an option (which also means I need an opt in/opt out page for them
"""


app = Flask(__name__)
app.debug = True
#SSLify(app) #TODO: https://github.com/kennethreitz/flask-sslify forces https:// URLs; this is necessary to protect the session cookies, obviously

logins = LoginManager(app)

app.secret_key = os.urandom(24) # set the key used for signing cookies
app.permanent_sessions = True #this is 
# or should I be using login_user(remember=True)??
# (i *don't* want to provide UI for this; either all sessions are transient or all are)
#app.permanent_session_lifetime =  this defaults to 31 days. is this a good idea?

app.config['KEY_BITSTRENGTH'] = 2056
app.config['ACCOUNTS_DATABASE'] = "./accounts.dbm"


# idea: is it any safer to use key = HMAC(k, password)? 
#  that's...essentially no better.

# 513 bytes has the useful property that it is 4104 bits, which is divisible by 6, the number of bits in each base64 character, meaning there's no need for padding
# and also that it is *at least* 4096 bits which is drastically over
# >>> [(i%6,i%8) for i in range(4096, 4096+10) if i%6==0 and i%8==0] == [4104]
# 255 also has this property
#  actually, any multiple of 3 bytes will have it...
#  because by definition, if we're in units of bytes, it's an even number of bytes
#  and if there's a 3 in it, then when you multiple by 8 to make it into bits, it's a multiple of 6
# so instead this:
#  pick the bitstrength you want b
#  find the nearest multiple of 3 above b: (ceil((b//8)/3)*3) ((close enough approximation: ((b//8)//3+1)*3, which is the same everywhere except for exactly multiples of 3 where it gives an answer 3 more, which doesn't really affect our cause
# Now, maybe this is too much? The defacto answer is that you get 21000 characters (or is that bytes??) for URLs: http://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers
#   and that that is pushing it
# if AES128 is still considered secure, maybe using 2056 is enough?
# question: is it possible to DDoS the system to get it to generate a gazillion fake accounts, using up entropy in the process
v
KEYLENGTH = ((app.config['KEY_BITSTRENGTH']//8)//3+1)*3


## Essay:
## People to talk into serving this:
# the indiewebcamp people, including singpolyma
# silverwizard
# and subscribers:





class User(UserMixin):
	"""
	A user has a UUID for an ID (obvious choice)
	but they also have an "identity", which is a string uniquely identifying the person that is (looks like) a URN:
	e.g.:
	 local:username
	 mailto:username@server.com
	 openid:http://username.livejournal.com
	 oauth:https://facebook.com/user.name
	 oauth:http://twitter.com/username
	 oauth:http://github.com/username
	 xmpp:username@server.com
	 sms:+155590901122 #danger! money!
	(it would be nice if all of these 
	(notice that these are compatible with the rel=me formats from IndieAuth: https://indiewebcamp.com/IndieAuth, but I'm not sold on IndieAuth itself so I'm not supporting it)
	and (CURRENTLY UNIMPLEMENTED) a friendly name (.nickname), which is used for commenting (ALSO UNIMPLEMENTED)
	and a user icon (.img)
	 -- for identity providers that offer it (facebook, twitter), the friendly name and icon should be pulled from their account
	# UX Aside: if .nickname is missing (bool(nickname) == False) then you should use .identity instead
	#   to make this more palatable, typeset it in fixed width font and prefix with an underscore
	
	the idea is that when someone Federated-Friends you they assert their right over an identity, and you give them a local identity attached to that
	 so be careful:
	.id is the *local* identity that we use as a primary key
	.identity is the *global* identity that
	Q: why not merge the two? Flask-Login doesn't care, afterall. It just needs unique strings. If someone is asserting an identity, they definitely are getting a unique string
	A1: if we did that, would you hit /auth/mailto:you@server.com/key ? I am wary of embedding someone's personal identity into this address, even if they're not supposed to give it out.
		-(though maybe embedding your identity into the string makes it easier to explain that it logs you in....
		- alternately, maybe the key is enough by itself without the identity; this means scanning the database to find (which is expensive unless we index by key)
	A2: I don't know that identity strings will always be URL safe, though if they're actually URNs they should be...
	A3: the indirection makes it possible to change identity servers without losing your accoutn, e.g. if someone wants to switch to using twitter or github or IndieAuth
		- (but is this really likely? again, it's probably simplest just to assume that people would rather make a new account and tell everyone "this is the new me" than recover an old one; certainly in an informal setting like a comment thread, the social mechanisms are going to dominate over the technical ones)
		- the motivation for linking multiple identities together is that people use a lot of services and as those services morph into also being identities, being stuck on any one in particular is bad
		  but this system. i could, for example, allow people, if they are already signed in, to change their identity (if they can prove a new one; in case of local: they automatically get it so long as no one else has it yet, and the old one is..what..retired?  oh but then you see the issue: if we don't use UUIDs but just use URNs, *and* we allow people to change them, then local: identities could be stolen)
	
	# in 4chan terms, identity is like the name field, key is like the tripcode field	

	# I guess this is a UX question
	 in principle then you can reset, but more commonly people will just sign in with a new identity (i.e. consider that it's much more common for people to make a new account and re-add all their friends instead of recovering it when facebook kicks them off)
	
	And in this system, each user has a key attached, i.e. a password, but unlike normal passwords we generate them and users don't need to memorize them, just save them in a bookmark,
	 so it is more like a physical key or a bank card
	# TODO: put the keys in a separate table?
	
	# Oh, key point:
	# user logins are recorded: (IP address, user agent, datetime)
	# and there will be a submodule that shows unusual activity (to both the admin and each user)
	
	# Weak points:
	# - enforcing that we have a proof token that someone owns an account (we should probably make people reprove their ownership of accounts regularly)
	#  consequences of getting this wrong: on my site (but only on my site) someone can impersonate someone else, and eventually people stop trusting the names they see on my site. maybe. if they are paying attention.
	"""
	# Q: should I have a different user for different login sources? e.g. FacebookUser, OpenIDUser, EmailUser..?	

	
	DB = UserDB(app.config['ACCOUNTS_DATABASE'])
		
	@classmethod
	def create(User, identity, nickname="", img=None):
		"""
		Make a new user
		this also *immediately persists* the user to storage, so login_user() should immediately work
		"""
		id = uuid.uuid4() #.bytes gives the raw bytes, which uses half the space, but using ascii is just a lot safer all around, e.g. we can store account IDs in XML or plaintext or JSON without worrying too much), and plus Flask-Login wants strs (it actually knows them as "unicode", in a py2k throwback)
		# TODO: double-check that ID has never been used? does UUID *guarantee* uniqueness or just make it *very likely*?
		key = os.urandom(KEYLENGTH)
		return User(id, key, identity, nickname, img)
	
	@logins.user_loader
	@classmethod
	def load(User, id):
		# ...
		# look up ID in the database to get identity 
		# XXX we should proooobably lock the database here
		# --- do we scan keys
		if id not in User.DB:
			# a user loader has to return None on invalid users
			return None
		
		return Users.DB[id]
	
	def __init__(self, id, key, identity, nickname="", img=None):
		self.id = id
		self.key = key
		# TODO: enforce types
		self.identity = identity
		self.nickname = nickname
		self.img = img
	
	@property
	def friendlyname(self):
		return self.nickname if self.nickname else self.identity
	
	@property
	def url(self):
		"""
		If .identity has 
		If nothing is given, returns None, and the UI should reflect this state by *not* wrapping the
		i.e.
		"""
		if self.identity.startswith("oauth:") or self.identity.startswith("openid:"):
			return self.identity.split(":",1)[0] #cut off the urn prefix
		if self.identity.startswith("mailto:"): 
			return self.identity   #include the mailto: prefix
		return None
	
	@property
	def link(self):
		if self.url:
			return "<a href='%s%>%s</a>" % (self.url, self.friendlyname)
		else:
			return "%s" % (self.friendlyname,)
		


@app.route("/friend", methods=["GET","POST"])
def friend():
	"""
	'friend' this blog: generate a private subscription link and notify the owner that they have a new subscriber to vet
	"""
	if current_user.is_authenticated():
		return "You have already friended this blog.", 403
		# TODO: maybe this should be where you can reset your password?
	# otherwise: jump them to the new user page
	# ah, this is complicated. because *sometimes* we want
	# so... we should... render a page where they can choose what auth method they want
	#  then they click an auth method, and dive through some hoops, at the end of which they ... send us... something... which proves that they own a particular identity 
	#  XXX is watching the session important here?
	# so now I need to get into templates, finally
	# we could: take POSTs to /friend (we should probably only)
	#  okay, simplest: someone clicks "username" in the radio box then hits submit; we look in the database to see
	#  second simplest: someone clicks "email" and types in an email, then hits submit
	# (UX: the javascript should only show the relevant piece of the form)
	return render_template("friend.html")

@app.route("/friend/claim/<identity>")
def claim_identity(identity):
	
	login_user(User.create(identity).id)

# TODO: instead of taking a key over the URL (i.e. plaintext auth, which is secure *if* TLS is secure *and* your use of TLS is secure, *AND* if no one leaks the link by accident)
@app.route("/auth/<key>")
def login(key):
	# TODO: if someone hits this over HTTP *immediately invalidate the key*
	# basic assumption: my threat model does *not* including people brute forcing. they can try. they have a small chance of compromising an account or two. fail2ban can help.
	# --- in principle, someone 
	
	key = urlsafe_b64decode(key) #convert to bytes
	if key not in User.DB:
		return "Nope.", 401
	else:
		u = User.DB[key].id
		if current_user.is_authenticated():
			if current_user.id != u:
				# TODO: use flashing + redirecting to /index here
				return "You are trying to login as a different user. If you intended to do this you should <a href='%s'>logout</a> first. If you did not intend to do this, someone may be trying to fixate your session." % (url_for("logout"),), 400
				
				# here's an interesting case: what happens if someone follows the auth link *as someone else*?
				# here's a session fixation attack that this opens:  make a throwaway account and get its key. that key is like a session ID, but worse because it doesn't ever change.
				#         send the victim blog.com/auth/<attackerkey>?next=http://msn.com. this silently switches accounts.
				#         now the attacker and victim are sharing an account. if the victim doesn't notice, they might put up sensitive data
				#  the victim will get out of it the next time they follow their RSS feed
				# does forcing manual logout help?
				# answer: no
				# actually, the fixation attack has nothing to do. Someone could send you to /logout (guards: only accept logouts via POST?)
				# the sticky point is that I'm conflating identity
				#  the reason long keys work for google docs and dropbox is that those keys protect the pages
				# but i'm designing this to protect the identity
				# why is that broken?
				#  - the issue is per-page keys vs per-session keys, I think
				# with a per-page key, a single load. if someone makes you auth to
				# the reason keys work as identity 
				
		
		login_user(u)
		if request.query.get("next"):
			return redirect(request.query.get("next"))
		return "Hello %s" % (current_user,)


# damn
# damn damn damn
# this design totally is vulnerable to CSRF
#  https://en.wikipedia.org/wiki/Cross-site_request_forgery
"""
purerave is at least partially vulnerable to a mild form of CSRF: login forgery
 and login forgey is *exactly* what I'm opening up here, but because it's with GETs

GETs are not intended to be state-changing
 so i'm definitely going about this all wrong

my original goal was to protect articles
but then i was also like...well, maybe i want comments, too
 one idea: detangle reading and writing. my initial goal is confidentiality: I want to restrict who can see what I write
 a linked goal is restricting who can write on what I write: only people who can see a post should be able to comment on it, yeah?
  buttttt also I jumped to the idea of having

i can write a self-hosted disqus-like ajaxey widget where you sign in *to it* using credentials

do i want people to have accounts or not?
is there any way to have a seamless sign-on without GETs?
 ---> cookies? maybe? just set a long-lived cookie?
      but then what about when people clear their cookies or switch devices? that's no good..
      
  I think that state is the enemy here
  CSRF and XSS rely on stateful changes: you get someone to go to a page (CSRF) or you inject some code into a page (XSS) and then you have the rights of that user
  if instead of state (i.e. setting session variables) you just say, keep a token representing your identity in the URL and every page you click around keeps it, then what can happen?
    - the token could be passed around in Referer headers (sometimes the Referer gets stripped? like, moving from HTTP to HTTPS apparently? or the other way? i'm not sure)
    - the token could leak? I guess? there's lots of ways it could leak: screenshots, HTTP, proxies, someone breaking into your email
    - someone can still phish you by sending you their session-fixated link. but they can't do it behind your back (in an iframe/hidden div/etc).


/rss.xml
/atom.xml
/rss.<key>.xml
/atom.<key>.xml

when you download /rss/<key>.xml
"""

#########



from flask_acl import *


"""

If I've settled on having users afterall then I think this is best done as two orthogonal flask extensions:
a. flask-login-less
  -> this shoves a user key into every URL. views are written as normal, there's just some code in before_request and in url_for which handle this.
     or maybe it uses session cookies, but it just goes once through a GET (which is really not how GET is supposed to work, but I need it to make bookmarking work)
     and then shoves the auth into session cookies like normal, but if that's 
      the advantage to the former is a) people have sorta been trained that long random URLs == authorization so they'll be careful, maybe b) you can't trick someone into using the wrong account
       oh wait, but of *course* you can trick them into the wrong account with the former: just post "hey, look at this article"
       bleh
       well, if i want to continue with this idea, how can i mitigate?
       a) pin the session?
       b) 
      
b. flask-acl



acl = ACL(app)

@acl.readable
def readable(page, user):
	"implement"
	"None -> unaht

@acl.public
@app.route("/rss.xml")
def public_rss():
	return ...

@acl(readers, writers=None)
@


when a view is requested by GET, HEAD, OPTIONS
if it's requested by
if the predicate is actually a set (or something coerceable to a set), this callable is used:
lambda p: p in set(A)
   (but is this useful? doesn't this imply hard-coding accounts?)

maybe a better idea is this:
 instruct people that if they want to have nice, readable, metagroups, do something like: @acl(lambda p: admins(p) and not angry(p))
hmm
if i'm making an ACL structure does that mean I'm imposing a group structure too?

def post_readers(user, fname):
	if fname not in PERMISSIONS: return None # default to no
	perms = PERMISSIONS[fname]
	if perms == Perms.PUBLIC:
		return True
	if perms == Perms.PRIVATE: #XXX timing attack??
		return user == owner # XXX should PRIVATE be folded as LOCKED with only owner in the set?
	if perms == Perms.LOCKED:
		
		
@route("/post/<path:fname>")
@acl(post_readers)
def post(fname):
	return render_template("post.html", content=open(fname), comments=[(c.uid,c.date,c.content) for c.uid,c.date,c.content in COMMENTS if c.permalink == fname])

#<-- wait, this is wrong. if a post is world-readable then everyone can read, but not everyone should be able to comment
# though
# also
post_commenters = post_readers #but you could 

@route("/post/<path:fname>", methods=["POST"])
@acl(None, post_commenters)
def post_comment(fname):
	request.args.c
	return redirect(url_for(post, fname=fname))



c. something that makes (python-social-auth??) -- this should come with templates


"""

@app.route("/logout")
def logout():
	# CSRF DANGER:
	#  anyone can trick you into logging in as a chosen account (a session-fixation attack)
	# to guard against this we:
	# - refuse to login if there's already an active
	#  you must not be able to log out the user except from this site
	logout_user()
	return redirect("/")




@app.route("/")
def index():
	return render_template("index.html")


# FEATURE: if you sign up with an email, you should be able to get email pings instead of having to use RSS (Wordpress.com offers this; it's very handy)
# actually, *ideally*, if you sign up with anything you should get pings, e.g. if you sign in with facebook then my feed should automatically end up in your FB feed, but that's... more complicated and probably not possible, not to do privately anyway

# FEATURE: admin needs to be able to invalidate all accounts

app.logger.info("Using %d byte passwords" % (KEYLENGTH,))

# 4096 bits of random, = 

if __name__ == '__main__':
	app.run()
