
from flask import *

# Flask-Login's __all__ is wrong: things that are clearly required to use the public API are missing
import flask.ext.login
flask.ext.login.__all__ += ["login_user", "logout_user", "current_user", "UserMixin"]

from flask.ext.login import *
from flask_loginless import *
from flask_acl import *

import os, time
import datetime

app = Flask(__name__)
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


@app.route("/")
@acl.public
def index():
	return render_template('index.html', blogtitle=BLOGTITLE)


# TODO:
#  the idea is that some pages (/index, /manage) will have fixed permissions coded at the app level
#  but for everything under /post, we delegate to the external, user-controlled, database
@app.route("/post/<path:path>")
#@acl(lambda user, path: database_acl(user, path))
@acl.public
def view_post(path):
	return render_template('post.html', blogtitle=BLOGTITLE, title=path,
		#content=Markup(open(os.path.join("_posts", path)).read()),
		comments=[])


# things I could do:
# - make acl take EITHER a set or a predicate
# - make ACL know about sets (this is probably the most common use
# - 

@app.route("/post/family")
@acl(lambda user: user.get_id() in family)
def view_post_family():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Family-Accessible Post")

# in flask, an "endpoint" is a unique string + function
# usually the unique string is function.__name__, but this can (argh) be overridden
# I want to attach ACLs to functions, but in Flask that means attaching them to endpoints
# request.url_rule.endpoint gets the currently active endpoint string (after parsing and routing happens)
# (and request.view_args gets the values for any variables marked by <varname> syntax in the route string)
# 

@app.route("/post/friends")
#@acl.allow(admins)  #maybe let the ACLs stack? 
@acl(lambda user: user.get_id() in friends)
def view_post_friends():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Friend-Accessible Post")

@app.route("/post/public")
#@acl(lambda user: True)
#@acl.public
def view_post_public():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Public-Accessible Post")

@app.route("/post/default")
def view_post_default():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Default-Perms Post", content="This should be inaccessible to everyone. Except maybe the owner. I guess. But then we'd have to give Flask-ACL a notion of owner groups...")


@app.route("/manage")
@acl(lambda user: user.get_id() in admins)
def manage():
	if request.method == "POST":
		# ... handle stuff
		# sending a redirect should skip the "Do You Want To Resubmit This Form?" behaviour? I think?
		return redirect(url_for("manage"))
	return render_template('manage.html')


# XXX DEBUG: this lets anyone login as anyone. It's for *TESTING* only. It's a giant, obvious, backdoor.
@app.route("/login/<user_id>")
@acl.public
def login(user_id):
	login_user(app.login_manager.user_callback(user_id))
	app.logger.debug("Logged in %s as %s", user_id, current_user.get_id())
	return redirect(url_for("index"))

@app.route("/logout")
@acl.public
def logout():
	logout_user()
	return redirect(url_for("index"))


#Inspiration: petnames
# http://www.skyhunter.com/marcs/petnames/IntroPetNames.html
# this isn't quite a petnames system, but it does exploit:
# - linking keys to shorter names
# - storing the mappings decentralized
# 

if __name__ == '__main__':
	if __debug__:
		app.run(debug=True, use_reloader=False)
	else:
		app.run()
