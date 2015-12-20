# Why Everything Sucks

By Kousu

Life's a bitch **then you die**.

* 1 trustno1
* 2 eat a cochon
* 3 pencils
* 9 Killa Bigga



```

@app.route("/edit/<post>", methods=["GET","POST"])
@acl.allow(admins)
def editor(post=""):
        app.logger.debug("editor(); post=%s", post)
        if request.method == "POST":
                # expect JSON?
                app.logger.debug("%s", request.form)
                msg = request.json #  #awesome! yay flask
                msg = request.form #<-- actually we have to do this...
                app.logger.debug(msg['content'])
                content = msg['content']
                title = extract_title(content)
                slug = slugify(title)

                app.logger.debug("Received content for '%s' with ACL '%s'", post, msg['acl'])
                if msg['command'] == "draft":
                        raise NotImplementedError
                elif msg['command'] == 'post':
                        app.logger.debug("Writing to disk")
                        # write to disk
                        # TODO: catch renames. a rename should wipe out the old files.
                        with open("_posts/" + slug + ".md","w") as md:
                                md.write(msg['content'])
                        with open("_posts/" + slug + ".acl","w") as acl:
                                acl.write(json.dumps(msg['acl'].lower().split()))

```
