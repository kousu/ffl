#!/usr/bin/env python3

import os.path
import mimetypes
from flask import Flask, Response

import logging
logging.basicConfig(format="%(levelname)s: %(message)s")
logging.getLogger().setLevel(logging.DEBUG)


app = Flask(__name__)

@app.route("/<fname>", methods=['GET'])
def guarded_get(fname):

	type, encoding = mimetypes.guess_type(fname) # we may edit fname, so do this first
	logging.info("Guessing %s is %s+%s" % (fname, type, encoding))

	# XXX sanitize ".."s?!
	fname = os.path.abspath(os.path.join(".", fname))
	logging.debug("fname = %s" % (fname,))
	if os.path.exists(fname+".locked"):
		# the resource is locked
		if os.path.exists(fname):
			logging.warn("Both %s and %s.locked exist.")
		fname = fname + ".locked"
	elif os.path.exists(fname):
		pass
	else:
		return Response("<html><body><h1>%s Not Found</h1></body></html>" % fname, 404)
	
	# TODO: mimetype sniffing?
	# TODO: what if we can't open the file? what then?
	return Response(open(fname), 200, mimetype=type)


if __name__ == '__main__':
	app.run(debug=__debug__)
