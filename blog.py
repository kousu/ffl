
from flask import *

# Flask-Login's __all__ is wrong: things that are clearly required to use the public API are missing
import flask.ext.login
flask.ext.login.__all__ += ["login_user", "logout_user", "current_user", "UserMixin"]

from flask.ext.login import *
from flask_loginless import *
from flask_acl import *

import os, time


app = Flask(__name__)
app.secret_key = os.urandom(50)

lm = LoginManager(app)

acl = ACL(app)

class User(LoginTokenMixin, UserMixin):
	@classmethod
	def reload(cls, id, display_name, creation_date):
		return cls(id, display_name, creation_date)
	
	def __init__(self, id, display_name=None):
		self.id = id
		if display_name is None: display_name = id
		self.display_name = display_name
		self.creation_date = int(time.time())




BLOGTITLE = "Kousu's Magical Fantasy Land"

# define some test user groups
# The limitation of unix permissions is that each file has *exactly one* group it can be in
#  and these groups are
#   - not user editable
#   - 
owner = {"kousu"}
family = {"sister", "brother", "mom", "dad", "aunt"}
friends = {"oauth:https://facebook.com/sally", "oauth:https://facebook.com/sanchez", "mailto:jack@gmail.com"}


@app.route("/")
@acl.public
def index():
	return render_template('index.html', blogtitle=BLOGTITLE)


# TODO:
#@app.route("/post/<path:path>")
##@acl(lambda user, path: check_file_acl(user, path))
#def view_post(path):
#	return render_template('post.html', blogtitle=BLOGTITLE, title=path, content=Markup(open(os.path.join("_posts", path)).read()), comments=[])


@app.route("/post/family")
@acl(lambda user: user.get_id() in family)
def view_post_family():
	return render_template('post.html', blogtitle=BLOGTITLE, title="Family-Accessible Post")

@app.route("/post/friends")
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
	return render_template('post.html', blogtitle=BLOGTITLE, title="Default-Perms Post")



if __name__ == '__main__':
	if __debug__:
		app.run(debug=True, use_reloader=False)
	else:
		app.run()
