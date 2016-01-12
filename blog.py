"""
Prototype self-hosted ACL-controlled blog, based on distributed identity (i.e. identity servers aka "social sign on" or plain old email)
Usage:
`python blog.py & surf http://localhost:5000`


Future plan:
 - pieces of this will get extracted to StaticACLs
   which will just be a system---I guess a Flask Blueprint, probably---
   that hooks ACLs onto every file under it, each of which has a
   .acl file to go with and a plaintext user/groups database.
   
   Then plug in a static site generator (*cough*Jekyll*cough*) with
   this server in front to enforce the ACLs but nothing more: no moving parts (i.e. no state).
   
   To be ideal, there will have to be *some* moving parts: to generate new subscriber feeds
   (if there were no moving parts, you would need to hand-add all your friends to text files,
    and that seems a little bit absurd)

 - Static sites are nice, but not every site wants to be static
"""

"""
TODO

Security:
- [ ] Directory traversal is definitely possible in a lot of places. I'm a little bit surprised Flask doesn't stomp that in the nuts.
- [ ] Give 404 instead of 401 for ACL failures, but only on view_post: post titles give away secrets, sometimes, so we want to do our best to avoid leaking what we can.



UI:
- [ ] Use a <textarea> editor so that if javascript isn't running the posts can still be edited, just not as smoothly
- [ ] Put the editor inline on the post page: clicking "Edit"
  (hmmm how well does this work without javascript I wonder... is javascript a fair assumption?)
  --- EpicEditor is pretty javascript heavy, but there's 
- [ ] A publish date widget. New posts get now, edited posts get set to their old date.

UX:
- [ ] What resolution on post dates should there be? Should there be a min/max date?
- [ ] Should 'private' or 'public' need to be alone in the perms field, or should they be special cases that live alongside but override the others?
  - Pro alone: the cognitive load is simpler
  - Pro together: you could write a list of people *to* publish to but then
- [ ] Should there be Drafts distinct from just Private posts?
  - LJ doesn't have drafts. So yeah, probably just keeping things `private` is enough.
- [ ] How should permissions work? I want the simple to be simple (and safe!) and the complex possible.
  - Here's LJ's design: http://www.livejournal.com/support/faq/24.html
    Their UI has a simple dropdown with 3 elements {public,friends,private} and a fourth "custom" which opens up a sub-UI for selecting groups (+s). There's no way to do -s explicitly.
    The first three have distinct icons; the fourth has the same icon as "friends" except to the owner, who sees.

Data:
- [ ] Store post dates in UTC instead of in whatever the server's timezone is --- but use the client's ..local..? time? (<input type="datetime-local"> would solve all these, because it always gives Zulu time to the API but local time to the user, but no browsers support it yet)
- [ ] Frontmatter parsing
  Here's how jekyll does it, for compatibilty: https://github.com/jekyll/jekyll/blob/92ba22f8fe30dc9bbe53585f60586c77e7cc3e14/lib/jekyll/document.rb#L269
  basically: it regexes for ---<stuff>---, parses <stuff> as YAML and takes whatever comes after (via the perlesque magic variable $POSTMATCH) as markdown
  that's not a terrible way to do it.

Testing:
- [ ] Write some unit tests!
"""

from flask import *

# Flask-Login's __all__ is wrong: things that are clearly required to use the public API are missing
import flask.ext.login
flask.ext.login.__all__ += ["login_user", "logout_user", "current_user", "UserMixin"]

from flask.ext.login import *
from flask_loginless import *
from flask_acl import *

import markdown, bleach

import os, time
import json
import datetime, dateutil.parser # such laze

from functools import *

import random



from utils import *


app = Flask(__name__)
#app.debug = True
app.secret_key = "bloggy" #os.urandom(50)

lm = LoginManager(app)

acl = ACL(app)

class User(LoginTokenMixin, UserMixin):
	"this is a really silly user class. it has no consistency checking at all"
	@classmethod
	def reload(cls, id):
		display_name = id.title()
		#creation_date = datetime.datetime.now()
		return cls(id, display_name)
	
	def __init__(self, id, display_name=None):
		self.id = id
		if display_name is None: display_name = id
		self.display_name = display_name
		self.creation_date = int(time.time())

lm.user_loader(User.reload)

BLOGTITLE = "Kousu's Magical Fantasy Land"

# define some test user groups
# The limitation of unix permissions is that each file has *exactly one* group it can be in
#  and these groups are
#   - not user editable
#   - not composable
#  so there's no way to express things like "give to all salespeople except those who are overseas" or "show to everyone on my friends list except my boss"
# they work alright to express capabilities, things like "can use the soundcard" "can use the video card" "can tweak network settings", so long as each of these are totally independent
admins = {"kousu"}
family = {"sister", "brother", "mom", "dad", "aunt"}
friends = {"oauth:https://facebook.com/sally", "oauth:https://facebook.com/sanchez", "mailto:jack@gmail.com"}
randoms = {"anon2342", "anon324234"} # people who have followed us but that we have not accepted, roughly equivalent to a Friend Request that goes nowhere



UserDB = admins.union(family).union(friends).union(randoms)
subscribers = UserDB - randoms
Groups = {"admins": admins, "family": family, "friends": friends, "subscribers": subscribers} #randoms don't get a group: you cannot give them posts. you must move them to Subscribers first.


@app.route("/")
@acl.public()
def index():
	return render_template('index.html', blogtitle=BLOGTITLE)


# ^ this should really be reusing the code in flask_acl somehow
# the code that composes an ACL out of sub-rules is in acl_for
# which is right now just calling out to this
# like, sorrrrta what I want is to call acl.allow() when I find a "+" and acl.deny() when I find a "-"
#  idea: if I somehow worked out how to do that
#  for that to work, I 
# I have a caching problem (of course):
#  how do I get the ACL data from the disk to the ACL structure
#  and how do I do it on every request (actually, i can probably be a bit smarter: I only need to do it a) when the timestamp on the .acl file changes b) when the timestamp on the .group files change)
# idea 1: add an acl.clear(request.url_route.endpoint)
# okay, next: how do I reload?
# well, 
# next: do I want to keep the ACL as a materialized set, one per view
#    or do I keep it as a list of predicates?
#    I could also keep it as a list of sets, which is probably easier on the memory since views can share

# I sort of like sets and materializing the whole thing simply because they let me write acl_for(), which is very useful for UI: a user
#  but maybe the more common UI case is "does X have access" and that can be done even if choose not to materialize...
# TODO: figure out if it's more common for allowed or denied to shortcircuit and therefore which of any/all to use (one can be converted to the other by de moivre with suitable application of nots)
# allowed = any(current_user.get_id() in set(pred(**request.view_args)) for pred in allows) and not any(current_user.get_id() in set(pred(**request.view_args)) for pred in denies)
#  lets see, any() will shortcircuit if one passes. one will pass if the person is in the denied set. but mostly people are not in denied sets, probably?
#  or any will pass if user is in the allowed set, but again these sets are small comparitively?
# TODO: cache. but be careful not to introduce TOCTOUs!!



from collections import namedtuple	

def interpret_ACL(perms):
	" load the ACLs : translate a string like 'friends -family -mailto:sally@gmail.net' into an actual set "
	
	allows, denies = set(), set() # <-- default deny
	app.logger.debug("perms = %s", perms)
	if perms == "public":
		allows = public_set
	elif perms == "private":
		pass
	else:
		if isinstance(perms, str):
			perms = perms.split()
		
		def to_set(e):
			if e in UserDB: return {e}
			elif e in Groups: return Groups[e]
			else:
				app.logger.warn("Unknown user %s", e)
				return {e} #DEBUG : accept unknown users off disk
				#return set()
		
		allows = {to_set(rule[1:]) for rule in perms if rule[0] != "-"}
		denies = {to_set(rule[1:]) for rule in perms if rule[0] == "-"}
	
	
	return namedtuple("",["allowed","denied"])(allows, denies}


@app.before_request
def share_acl():
	g.acl = acl


def flask_memoized(f):
	"""
	Memoize a function using the Flask `g` magic global
	this means that rather than it effectively gets wiped on each request
	This object exists precisely because because with all the lambdas and decorators flying around flask, it's hard to share values between difference components
	so this function lets you write code which has a consistent value for the duration of a request, but then flips back to something else on the next request
	"""
	@wraps(f)
	def dec(*args, **kwargs):
		if not hasattr(g,f.__qualname__):
			setattr(g,f.__qualname__,{}) #create the memoization space; this is inside the decorator because it has to be redone on each request
		
		memos = getattr(g,f.__qualname__)
		
		k = (args, tuple(sorted(kwargs.items())))
		if k not in memos:
			memos[k] = f(*args, **kwargs)
		return memos[k]

	return dec

memoized_load_post = flask_memoized(Post.load)
memoized_interpret_ACL = flask_memoized(interpret_ACL)

# TODO:
#  the idea is that some pages (/index, /manage) will have fixed permissions coded at the app level
#  but for everything under /post, we delegate to the external, user-controlled, database
@app.route("/post/<path:post>")
@acl.allow(admins)
@acl.allow(lambda user, post: user.get_id() in memoized_interpret_ACL(memoized_load_post(post).ACL).allowed) #OMG we're loading the post THREE TIMES per request. frig. What do? memoizing is the obvious answer, but how do I memoize a constructor??
@acl.deny (lambda user, post: user.get_id() in memoized_interpret_ACL(memoized_load_post(post).ACL).denied)
def view_post(post):
	post = strip_traversals(post)
	
	try:
		post = Post.load(post)
	except FileNotFoundError as exc:
		return str(exc), 404
	
	return render_template('post.html', post=post,
				comments=[{"author":"sally","text":"go eat Dumbo"}, "empty flasks", 4324])


# things I could do:
# - make acl take EITHER a set or a predicate
# - make ACL know about sets (this is probably the most common use
# - 

@app.route("/post/family")
@acl.allow(admins)
@acl.allow(family)
def view_post_family():
	return render_template('post.html', title="Family-Accessible Post")

# in flask, an "endpoint" is a unique string + function
# usually the unique string is function.__name__, but this can (argh) be overridden
# I want to attach ACLs to functions, but in Flask that means attaching them to endpoints
# request.url_rule.endpoint gets the currently active endpoint string (after parsing and routing happens)
# (and request.view_args gets the values for any variables marked by <varname> syntax in the route string)
# 

@app.route("/post/friends")
@acl.allow(admins)
@acl.allow(friends)
def view_post_friends():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Friend-Accessible Post")

@app.route("/post/public")
@acl.public()
def view_post_public():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Public-Accessible Post")

@app.route("/post/default")
def view_post_default():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Default-Perms Post", content="This should be inaccessible to everyone. Except maybe the owner. I guess. But then we'd have to give Flask-ACL a notion of owner groups...")


@app.route("/manage")
@acl.allow(admins)
def manage():
	if request.method == "POST":
		# ... handle stuff
		# sending a redirect should skip the "Do You Want To Resubmit This Form?" behaviour? I think?
		return redirect(url_for("manage"))
	return render_template('manage.html')


# XXX DEBUG: this lets anyone login as anyone. It's for *TESTING* only. It's a giant, obvious, backdoor.
@app.route("/login/<user_id>")
@acl.public()
def login(user_id):
	login_user(app.login_manager.user_callback(user_id))
	app.logger.debug("Logged in %s as %s", user_id, current_user.get_id())
	return redirect(url_for("index"))

@app.route("/logout")
@acl.public()
def _logout():
	logout_user()
	return redirect(url_for("index"))

@app.route("/rss.xml")
@acl.public()
def rss():
	# TODO: feedgenerator
	raise NotImplementedError("RSS is not implemented.")

@app.route("/subscribe")
@acl.public()
def subscribe():
	if current_user.get_id():
		return "%s, you are already subscribed." % (current_user.get_id(),), 403
	
	
	# TODO: put interstitials in here which
	# a) let you select your identity method (pseudoanon (like this), email, sms, 
	# b) guide you through completing -- which in some cases (sms, email) is not direct -- or is OAuth or OpenID which do lead you directly back
	# c) then create the account and give out the link
	
	# make a random, anonymous user
	login_user(User("anon%08d" % random.randint(0, 10**8), "Anonymous Coward"))
	global randoms
	randoms |= {current_user.get_id()}
	
	return "Add this link to your feed reader: <a href='%(url)s?next=%(rss)s'>RSS</a>" % {"url": url_for("auth", key=current_user.get_auth_token()), "rss": url_for("rss")}

# just tested: Liferea, at least, properly handles following the auth links and getting logged in
# so installing LoginLess and handing out https://blog.me/auth/<key>?next=/rss.xml as the login links is *precisely*

WORDS = [w.strip() for w in open("/usr/share/dict/words")]
def invent_slug():
	" make up a title on the fly, so that untitled posts (i.e. a tumbleblog) can happen "
	return "-".join(random.choice(WORDS) for i in range(random.randint(5,16)))

def html5_to_datetime(date, time):
	"given two isoformat strings, recover"
	# ???
	return dateutil.parser.parse(date+"T"+time)

def datetime_to_html5(D):
	return D.date().isoformat(), D.time().isoformat()


from io import StringIO
from itertools import tee


		

def load_post(post):
	with open("_posts/" + post + ".md") as f:
		content = f.read()
	with open("_posts/" + post + ".date") as f:
		published = dateutil.parser.parse(f.read())
	with open("_posts/" + post + ".acl") as f:
		perms = " ".join(json.loads(f.read()))

	return content, published, perms



@app.route("/edit/", methods=["GET","POST"])
@app.route("/edit/<path:post>", methods=["GET","POST"])
@acl.allow(admins)
def editor(post=""):
	post = strip_traversals(post)
	
	if request.method == "POST":
		# TODO: beware of CSRF! You should really use WTForms...
		# as written, anyone can trick your browser into posting anything to your blog
		
		title = extract_title(request.form['post_content'])
		app.logger.debug("post content: %s", request.form['post_content'])
		slug = slugify(title)
		app.logger.debug("POST /edit/%s: new slug=%s", post, slug)
		app.logger.debug("Received content for '%s' with ACL '%s'", post, request.form['post_acl'])
		app.logger.debug("Writing to disk")
		
		with open("_posts/" + slug + ".md","w") as f:
			f.write(request.form['post_content'])
		with open("_posts/" + slug + ".acl","w") as f:
			f.write(json.dumps(request.form['post_acl'].lower().split()))
		with open("_posts/" + slug + ".date","w") as f:
			published = html5_to_datetime(request.form['post_date'],request.form['post_time'])
			f.write(published.isoformat())
		
		if slug != post: #XXX this isn't truuuuuuuuuuuuuuuuuuuuuuue, because there might not *be* a title (in which case our slug 
			# a rename happened, so wipe the old file
			
			# get rid of the old copy
			try: os.unlink("_posts/" + post + ".md")
			except: pass
			try: os.unlink("_posts/" + post + ".acl")
			except: pass
			try: os.unlink("_posts/" + post + ".date")
			except: pass
		
		return redirect(url_for("view_post", post=slug))
	
	elif request.method == "GET":
		if not post: # new post!
			# new post
			live_link = None
			content = None
			perms = "private"

			published = datetime.datetime.now()
		else:
			try:
				content, published, perms = load_post(post)
				# read the title out of the markdown
				# the title is the first <h1> title, as far as we care
				assert slugify(extract_title(content)) == post, "When loading an existing post, slug from the post content should equal the title in the URL of the page!"
				live_link = url_for("view_post", post=post);
				
			except FileNotFoundError as exc:
				return str(exc), 404
	
		# we convert the datetime to isoformat as used by html5
		# we don't give a timezone (note: timezones only apply) so the timezone is implicitly whatever the *server* thinks
		# XXX this means that if you move countries your posts will all have timezone drift. this isn't a huuuge deal, but standardizing on zulu time would be better.
		# ( so: ideally the user input is implicitly in the timezones, but the storage is in UTC, which means at load/save time we need to convert, but otherwise)
		# ( datetime has tzinfo objects and .utcoffset() and some other things to help with this; I need to look into it
		# BEWARE: the timezone is ASSUMED TO BE UTC ('Z' for "Zulu time")
	
		# round minute down to nearest 15 minute interval, to match the 15-minute resolution
		# (the rendering of a time string is finicky in different browsers; not giving it the chance to deal with sub-minute resolution helps)
		# TODO: this should be a function since we need to also run it on incoming data --- since we can't trust the input!
		published = published.replace(minute = published.minute//15 * 15, second=0, microsecond=0)
		post_date, post_time = datetime_to_html5(published)
		
		return render_template('editor.html',
		                       blogtitle=BLOGTITLE,
		                       title="Editor",
		                       post_title=post, post_content=content, post_acl=perms, live_link=live_link,
	        	               post_date=post_date, post_time=post_time)


@app.before_request
def q():
	app.logger.debug("%s from %s", request.full_path, current_user.get_id())


if __name__ == '__main__':
	
	# XXX just playing with LoginLess
	import flask_loginless
	@lm.token_loader
	def i_dont_know_how_to_load_tokens(token): raise NotImplementedError("Token-loading is not implemented. Sorry bro.")
	flask_loginless.LoginLess(app)
	acl.public("auth")
	
	if __debug__:
		app.run(debug=True, use_reloader=False, host="0.0.0.0")
	else:
		app.run()
