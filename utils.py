

import re
from unicodedata import normalize

_punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')

def slugify(text, delim=u'-'):
    """Generates an slightly worse ASCII-only slug. A slug is a human-readable URL-safe string, like you see on wordpress/tumblr/everywhere"""
    # snitched from http://flask.pocoo.org/snippets/5/
    result = []
    for word in _punct_re.split(text.lower()):
        word = normalize('NFKD', word)
        if word:
            result.append(word)
    return str(delim.join(result))



import os.path
def strip_traversals(p):
	"sanitize directory traversals out of p"
	"the way this works is by pretending that p is at the root, normalizing the path so that ../s are all used up, and any that would have gone above the root become"
	return os.path.normpath("/" + p)[1:]

def test_strip_traversals():
	assert strip_traversals("holla/butters/../amiable/../../../../everything.html") == "everything.html"
	assert strip_traversals("holla/butters/../amiable/../everything.html") == "holla/everything.html"
	assert strip_traversals("holla/everything.html/jackdaw") == "holla/everything.html/jackdaw"
	assert strip_traversals("/holla/everything.html/jackdaw") == "/holla/everything.html/jackdaw"
	assert strip_traversals("") == ""

if __name__ == '__main__':
	test_strip_traversals()
	print("Tests passed")
