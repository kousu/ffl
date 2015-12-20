
from flask import *

# Flask-Login's __all__ is wrong: things that are clearly required to use the public API are missing
import flask.ext.login
flask.ext.login.__all__ += ["login_user", "logout_user", "current_user", "UserMixin"]

from flask.ext.login import *
from flask_loginless import *
from flask_acl import *

import markdown

import os, time
import json
import datetime

from functools import *

import random





app = Flask(__name__)
app.debug = True
app.secret_key = "bloggy" #os.urandom(50)

lm = LoginManager(app)

acl = ACL(app)

class User(LoginTokenMixin, UserMixin):
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

class public(set):
	"this represents the infinite, universal, set"
	def __init__(self): pass #disable the constructor
	def __contains__(self, x): return True
	def __str__(self): return "public"
public = public()
no1 = set()



UserDB = admins.union(family).union(friends).union(randoms)
subscribers = UserDB - randoms
Groups = {"admins": admins, "family": family, "friends": friends, "subscribers": subscribers} #randoms don't get a group: you cannot give them posts. you must move them to Subscribers first.


acl.public()
acl.public()

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

# so: an awkwardness about using sets is that they're immutable, which means that the sets they cover get fixed at @acl.{allow,deny} time, instead of at runtime
# fixes: use lists instead
#        use collections.MutableSet
#        use thunks
# another awkwardness about sets is they can't be parameterized on the view's arguments


def load_post_acls(path):
	" load the ACLs for view "
	" this is soooooooooooooooooooooo kludgy "
	# XXX design problem!
	# my ACLs
	# if my ACLs are predictates, then the predicates can handle
	# if my ACLs are sets, then I need to record an ACL for each (endpoint, view_args) combination
	# and since there's no way I can know these in advance....
	# bah
	# let's just see if I can get this working

	app.logger.debug("Loading ACLs for %s", path)
	
	# TODO: cache (but not memoize) this for speed
	# TODO: switch to yaml instead of json. it's more human-readable.
	#  also make sure to invalidate the cache whenever path's ACLs are updated
	
	allows, denies = set(), set() # <-- default deny
	try:
		perms = json.load(open("_posts/"+path+".acl"))
		
		app.logger.debug("perms = %s", perms)
		if perms == "public":
			allows = public_set
		elif perms == "private":
			pass
		else:
			app.logger.debug("loading perms from file")
			
			def to_set(e):
				if e in UserDB: return {e}
				elif e in Groups: return Groups[e]
				else:
					app.logger.warn("Unknown user %s", e)
					return {e} #DEBUG : accept unknown users off disk
					#return set()

			for rule in perms:
				type, principle = rule[0], rule[1:]
				principle = to_set(principle)
				if type == "+":
					allows.update(principle)
				elif type == "-":
					denies.update(principle)
				else:
					app.logger.warn("Invalid ACL rule %s on %s", rule, path)
	except Exception as exc:
		app.logger.info("Failed to load ACLs for %s. Defaulting to private.", path)
		app.logger.debug("%s", exc)
		raise
		pass
	
	return allows, denies

# TODO:
#  the idea is that some pages (/index, /manage) will have fixed permissions coded at the app level
#  but for everything under /post, we delegate to the external, user-controlled, database
@app.route("/post/<path:path>")
@acl.allow(admins)
@acl.allow(lambda user, path: user.get_id() in load_post_acls(path)[0])
@acl.deny (lambda user, path: user.get_id() in load_post_acls(path)[1])
def view_post(path):

	if os.path.exists(os.path.join("_posts", path + ".html")):
		content = open(os.path.join("_posts", path + ".html")).read()
	elif os.path.exists(os.path.join("_posts", path + ".md")):
		# note: there is a Flask-Markdown extension, which gives a filter you can use in templates (like `{{ content | markdown }}` but this is dumb)
		content = open(os.path.join("_posts", path + ".md")).read()
		content = markdown.Markdown().convert(content) #TODO: cache the Markdown instance
	else:
		# doesn't exist!
		return abort(404)
	
	content = Markup(content) #mark the content as 'safe' against XSS, so that it doesn't
	return render_template('post.html', blogtitle=BLOGTITLE, title="",
		content=content,
		comments=[])


# things I could do:
# - make acl take EITHER a set or a predicate
# - make ACL know about sets (this is probably the most common use
# - 

@app.route("/post/family")
@acl.allow(admins)
@acl.allow(family)
def view_post_family():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Family-Accessible Post")

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
def rss():
	raise NotImplementedError

@app.route("/subscribe")
@acl.public()
def subscribe():
	if current_user.get_id():
		return "Already subscribed as %s" % (current_user.get_id(),), 403
	
	
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

@app.route("/edit")
@app.route("/edit/<post>")
@acl.allow(admins)
def editor(post=""):
	if os.path.exists("_posts/" + post + ".md"):
		content = open("_posts/" + post + ".md").read()
	else:
		content = ""
	return render_template('editor.html', post_title=post, post_content=content)

@app.before_request
def q():
	app.logger.debug("%s from %s", request.full_path, current_user.get_id())

#Inspiration: petnames
# http://www.skyhunter.com/marcs/petnames/IntroPetNames.html
# this isn't quite a petnames system, but it does exploit:
# - linking keys to shorter names
# - storing the mappings decentralized
# 

if __name__ == '__main__':
	
	# XXX just playing
	import flask_loginless
	@lm.token_loader
	def fail(token): raise NotImplementedError
	flask_loginless.LoginLess(app)
	
	if __debug__:
		app.run(debug=True, use_reloader=False)
	else:
		app.run()
