Federated Friends Locking
=========================


## Quickstart

Install the dependencies. The quickest is
```
sudo pip install -r requirements.txt
```
but doing it manually with `pacman` or `apt-get` might work better for you.

Then run
```
python blog.py
```
and go [here](http://localhost:5000).


The rest of this README is a mess right now. Skip it unless you want to see my thought process.

# Explanation



Semi-public posts (blog or otherwise) are very useful, socially.
They allow engaging in the discussions on the public web,
without all the riskiness of being totally public,
and having all your history logged for inspection by doxxers or just jerks.

There are two methods of semi-public posts:
- have a pseudoanonymous name, and guard it carefully or dump it quickly (e.g. tumblr) -- hard to do right!! if the data is public it's still public
- have everyone on a central server (Livejournal, Facebook, G+)
- arrange a complicated federated-subscription thing, where users follow each other and then optionally can put followers into groups (Diaspora)
- don't (Twitter)

I have a simpler idea:
 Get people ("subscribers") to authenticate to you ("author") *once*.
 From the subscribers' perspective, instead of getting an account (in particular, instead of getting a password) to remember, they just get a customized RSS feed
   Instead of authing the feed each time, it is downloadable anywhere, but protected by TLS+a long random string, the way Google docs are.
 from your perspective, you get a notification when you get a new follower,
 just like normal, and you can accept them or not. when you accept them they get put into a default group ("Subscribers"?) and you have the option of adding others ("Friends", "Family", etc. the normal)
 but there is a subtle difference in what "accept" means from elsewhere:
 - the set of people you've accepted as friends is not public
 - people's subscription still behaves even without you accepting them
 - "accepting" doesn't mean "follow back" (because there's nothing standard attached to their authentication the way there is when you follow back within a centralized server)
 



Initial Authentication
----------------------

Also, ideally authentication is handled by an identity provider, so that users don't need to sign up for 
I think how I'm going to do this is python-social-auth
which is  unifying wrapper for OpenID, OAuth 1 and 2, and email authentication.
 STUMBLING BLOCK:
  - OAuth a) is *not* an authentication protocol, it's an *authorization* protocol
             it is meant for handing out capabilities, in the form of session tokens, so that mashup sites can e.g. pull your google calendar, access your twitter DMs, pull your profile data off facebook...
               people abuse it into being an authentication protocol (see: Soundcloud, Disqus, Livejournal)
               but it's really unweildy for this, and the original core author has bailed and railed against it
               nevertheless, it currently dominates "social login" because Facebook, Twitter, and Google support it and Facebook and Twitter *don't* support OpenID
          b) because it's meant for making apps interact, *every app must have app keys from *each* provider
             and an "app" means "a website"
             so every person who wants to use OAuth to log their friends into their blog must create a developer account at *each* site they want and deal with that bureaucracy
             which is bulllllshit

I think for a first draft, I will simply do use email auth:
- prove that you own an email (as sketchy as that is), and get the feed from that.
   -> need to protect against replays and whatnot; if you can do it stateless, even better

Or maybe just a single string without verification? after all, auth only happens once, so ToFU??


Repeat Authentication
---------------------

The goal is to avoid making the reader deal with auth as much as possible (if I make my friends sign in to read my blog none of them will read my blog)
So repeat auth is entirely via the 

 idea one: embed auth tokens (or session cookies) in URLs
 idea two: somehow have a landing page which puts session cookies 


idea one is stateless, and matches exactly how 100 works
idea two


Static Generator Requirements
-----------------------------

- I need metadata: particularly date: so that the index and RSS pages behave themselves, and perms: to contain the ACL
  -  [Jekyll's Approach To Metadata Is The Winner](http://jekyllrb.com/docs/frontmatter/)
- Set up git on commits to rerun the static generator
  - the static generator needs to extract metadata
    (apparently Jekyll *already does this*!)


- ACL METHOD ONE:  a StaticACL server, which enforces ACLs
    login can be handled by your choice of Flask-Social, Flask-LoginLess, Flask-Security, etc, whatever you feel is appropriate
    the simplest thing to do is probably to have the static generator extract the perms: string from fname.md to a file named .fname.acl
- ACL METHOD TWO:  at generation time, lock the real files away under _content/ (and if you can, set the perms so this cannot be read by the webserver)
   for each file:
     compute the set of users with access to a file and generate a custom address for them that contains their auth token via symlink:
      ln -s _content/post/cooking-badgers.html <token1>/post/cooking-badgets.html
      ln -s _content/post/cooking-badgers.html <token2>/post/cooking-badgets.html
      ln -s _content/post/cooking-badgers.html <token3>/post/cooking-badgets.html
     special case: if 'public', just symlink 
      ln -s _content/post/cooking-badgers.html /post/cooking-badgets.html
     ( or maybe ??
      ln -s _content/post/cooking-badgers.html /public/post/cooking-badgets.html )
   For each user:
     Compute the set of files they can see (`find /public -iname "*.html"; find /<token1>/ -iname "*.html"`)
     and generate index pages and RSS feeds from this

 Method one is simpler for me to implement, but it means moving parts: the StaticACL server still has to open/close .acl files and parse session cookies
   However it's a lot *less* moving parts than Wordpress.
 Method two means you can have a fully-static site (i.e. the only moving part is apache/nginx)
 and it also means it's really really easy to share links accidentally: if someone thinks your post is interesting and they link someone, that someone else now has the auth token (or something just as good)
   we can data-mine the logfiles to look for people doing this, but it's unreasonable to expect people not to share post links. so I *can't* do this.
  Mitigations:
    - stick a moving-parts server with Flask-Login in front. It can be super short: all it should do is rewrite /<path:path> -> either /public/<path> or /{{current_user.get_auth_token()}}/<path> or 404
      - this is like something mod_rewrite would do: change the path without changing the URL. But I don't think mod_rewrite knows how to look at session cookies.
    - wrap the whole thing in an iframe?? when you go to /<token>/<path> you get redirected to /path/ with has <iframe src="/_<token>/<path>">
 hmm
 So the KISS principle here is leaning against Method Two. Initially, it seems like a good idea: make the whole site static and your done. but doing that securely is ..hard. because...TOCTOU?
  but if I invest all the effort to write that code and generate those gazillion files and then I *still* need a webapp server, what's the point?
  
- (it would be nice if my work is reusable for non-static sites too; which is why Flask-ACL is written like it is..)

- I need a web editor (this part is *not* static):
  - trigger a git commit on edits
  - let you look back through the git history of a file
  PlainTextEditor:
   - just edit the raw file in a <textarea>
  MarkdownPostEditor:
    - use a fancy Markdown editor (if javascript is available)
      and metadata widgets like datetime and title(?), and the
      editor should understand metadata how to translate HTML5 widgets <-> YAML metadata.
    - supports attachments ---- getting this smooth is a hard UX problem, because you should be able to drop an image in and then preview the post and *see* the image, which might happen before the image is actually up on the server, so...?)
- To protect the web editor itself, either:
  - attack Flask-Login in front of it (@login_required)
  - simply generate an auth token for yourself and mv editor.html /editor_<token>.html. So then there's no login system needed, you just keep your token private.
     you could even set it up to PGP-email you a new token regularly
  or you can skip the editor entirely and just edit by ssh'ing in (or better: git clone + edit + git push)
  (but I would li
- Adding comments:
  - Add a mini version of the web editor (which is one-way only), that uses the same mechanism of retriggeringyou could trigger a rebuild
 These exist...somewhere
 The web editor is *not* part of the static site (so the static site should be a module, which Flask wants me to call a Blueprint)
  simplest way to deploy


Options:
* Jekyll (the most popular) (in ruby)
* https://github.com/andrejewski/reem (in javascript)


scraps
------

side idea: HTTP auth is broken, both digest and the challenge-response form
 but you could do the same idea but stronger---using hmac-sha2 instead of md5---with a bit of javascript (actually, with sjcl)
 and you could use privnote's trick of hiding a key in the #-mark anchor bit so that browsers never transmit the key
 in detail:
 your key link is site.com/auth/<userid>#<key>
 this page downloads sjcl and some javascript and a challenge string C (e.g. in a cookie), you compute H(k, C), put it in a cookie (which you can do from javascript, right?) and send it back; that cookie is then your auth token
  attacks: if someone can script inject (eg if you're not using HTTPS, or maybe XSS) then they can get the key and relay it to themselves

Really, the problem is the sign in step. That's what I'm trying to eliminate.
 The architectures already in place solve most of this.
 Really what I want
 HTTP auth (Basic and Digest) are no good. Basic auth is a joke --- it transmits the password in the clear
  Digest auth is vulnerable to downgrade attacks (pushing the auth to basic) which
  and it only uses MD5, which is dead, but cannot be removed due to stupid.
 also the UI is super shitty: 

 so basically cookies are better

my third idea is to look at the referrer header: in order to access /<x> you MUST access /<auth>/<x> first, and then
 either I record something in the (internal) Session or
 I reparse the Referer header (I could dig out Flask's route-matching subroutine, but I suspect it's not part of the public API...)

the problem with a cookie it only auths



USEFUL TIP:
 http://flask.pocoo.org/docs/0.10/patterns/appdispatch/
  you can write your app assuming it is single-user only (much simpler!)
  and then use WSGI middleware to generate and route to an app instance per user



I like capabilities because they are novel to me.


(( theme: use itsdangerous to do the syncookies trick: avoid keeping as much state as possible by making the client store it for us. send them base64'd-json with a MAC on the end ))


(( point: make sure not to fail open!! we need to prefer locked to unlocked ))
 maybe the best thing for this is:
  - GET /x first looks for x.locked; if it finds it it checks for a cookie containing base64(("x",timestamp,HMAC(k, ("x", timestamp))) and that timestamp > time.time()
      ((note: the tuples need to be suitable serialized first; struct.pack or pickle or something))
      if these pass, 200 and return the content
      if fail, 403 (or should we 404, so that people can't even get anything by guessing filenames?)
    else, look for x. if this is found, 200 and return it
    if not, 404
    Notice: this fails-closed: if /x.locked and /x exist then the second is ignored (and UX point: warn about these shadowing files at every opportunity)
            and there's no attached ACL list which, if deleted or erased from the file. It's just, is this world readable or not, and if not, a capability protocol.
  

we could wrap a pre-existing blog site in this by proxying: instead of asking the disk for x.locked and x, we ask another webserver for them
but it would be ungainly in other ways: how would you edit the blog posts in the first place?


UX points
--------
- when the private feed URL is handed out, it should be stressed that it is a *private* feed
- each friendslocked post should have a [THIS POST IS FRIENDSLOCKED] header
- links to ways to import it into systems people already use (LJ and tumblr can both syndicate feeds for you)
   (is there an FB syndicator? There seems to be companies that have made FB plugins which will relay RSS to a public facebook page
     e.g. http://www.ilovefreesoftware.com/09/webware/rss-to-twitter-facebook-myspace-linkedin-dlvr-it.html
     but there doesn't seem to obviously be any which take private feed and syndicate it into a facebook feed.
      I could..what... offer to give email notifications?)
- the privacy settings need to be integrated into the post editor. it must be doable at runtime.
  - the choices are "Public" or any set combination of groups (notated with +s and -s); also each subscriber is implicitly in a group of one, so that you can + or - individual people
  - since i don't necessarily want to tie this to any framework, i wonder if there can be and AJAX widget you drop on the post editor that handles this?
- if you could integrate your pre-existing PIM, especially the pre-existing PIM groups



Online Markdown editors:
* (from https://codegeekz.com/markdown-editors-and-tools/)
 the top of the pack seem to be:
 -https://code.google.com/p/pagedown/wiki/PageDown (aka StackEdit)
 -https://oscargodson.github.io/EpicEditor/
 - http://www.codingdrama.com/bootstrap-markdown/ --- has an excellent trick: *any* html tag can become a markdown block
    and can also work around textareas
    which is good for fallback...
   http://markitup.jaysalvat.com/home/ also works on textareas, but bootstrap-markdown looks cleaner
    anyway, basing on a textarea is probably a better plan because then we can design restricted-first
 -Dillinger, but it's too bloated for my taste
 - http://hallojs.org/demo/markdown/
 - https://github.com/cangelis/jquery-markdown
 semi-related: http://dropplets.com/ has beeeeeautiful CSS, but is nothing new elsewhere really



Feed Generators
* feedgenerator - "standalone django.utils.feedgenerator"
  used by pelican



Webmentions
-----------

The webmention spec is a stripped down version of trackbacks.
trackbacks/pingbacks needed an XMLRPC endpoint to handle stuff, which sort of implied a running database and a bunch of boilerplate.

Webmentions are more RESTful
The `protocol http://indiewebcamp.com/webmention-spec` is:
0. there are two URLs: sender and receiver. sender has 'mentioned' (think "commented on" or "reblogged" -- note: requires each comment to have a permalink of its own, which is not that unusual these days, but by no means universal or easy) receiver and wants to notify him.
1. Discovery: sender GETs https://receiver-site/postname and scans the HTML for <link rel="webmention">. If found, the href is taken as the "webmention endpoint".
2. Notification: sender POSTs http://receiver-site/webmention_listener {sender=<sender>, receiver=<receiver>}
3. Verification: receiver (asynchronously) GETs <sender> and scans the HTML for <receiver>.
4. (optional) receiver extracts microformats from the

This system lets anyone make the server hit any URL, simply by telling it lots of false URLs have mentioned one of its posts, which is a bandwidth amplification vuln.

This protocol is simpler on the wire, but it still uses endpoints and it still requires coordination.
If the protocol was *fully* RESTful then it would use the source and target URLs direct
I have a better design:
 Replace 1 and 2 with GET and Referrers:
   the webmention endpoint is *always* the receiver itself
   and notification is sender GETs receiver with `Referrer: sender` 
- This is 100% compatible with all existing systems: you don't need to put up weird POST handlers, and there's no need for discovery because if the receiver doesn't do webmentions it'll just ignore it as if it was any other browser request
- this requires some middleware, or mod_webmention, or something. but that's not unreasonable. the backend server can be entirely static.
 if receiver knows about webmentions, it can at that point spawn a subprocess to check the incoming link for mentions
   and instead of thinking of it as verification, make step 4 non-optional and instead think of the reverse GET as *finding the content*: you don't count it as a webmention unless you discover the mention microformat on the reverse link with a link to you.
 now, using Referrer means that every visitor who follows the link outwards will trigger you to poll again. for example, everyone incoming visitor will make you GET the google search they just came from
   so maybe instead of Referrer, use an X-Webmention: header. That won't be triggered accidentally, still doesn't require

the DDoS prevention issues are identical to those email has had to deal with, though the risk is smaller because nothing gets automatically posted if the attacker gets through
Idea: can the mention be signed? to further reduce DDoS surface?
if you run sender.com how can receiver.com know the mention came from you?
 idea one: just check IP addresses: is the incoming address the same as the server claimed in X-Webmention: (similar to SPF; actually SPF is more restrictive: you have to manually specify in a txt record which servers are which; hmmm. but DNS has multiple)
 idea two: stick a public signature key into DNS and sign the webmention with it (similar to DKIM)


References
==========

* http://indiewebcamp.com/ is a scattered working group of people very much in this direction
  right now they have:
  * a protocol "IndieAuth": 
    on your website's homepage (whatever GET / HTTP/1.1 on port 80/443 gives)
    put 'rel=me' links:
 <ul>
  <li><a href="https://twitter.com/aaronpk" rel="me">@aaronpk on Twitter</a></li>
  <li><a href="https://github.com/aaronpk" rel="me">Github</a></li>
  <li><a href="https://google.com/+aaronpk" rel="me">Google</a></li>
  <li><a href="mailto:me@example.com" rel="me">me@example.com</a></li>
  <li><a href="sms:+15554978477" rel="me">(503) 555-1212</a></li>
</ul>
   each of these hrefs is an identity provider

BUT: IndieAuth requires subscribers to do some work: namely, put this up online
 which means they need to have a domain and a webserver and HTML knowledge
 and also reveal all these identity things publically
 (kinda of cute: you can connect)

  * some principles
  * a bunch of ad hoc software which can syndicate personal blogs to the major services
    * including some Wordpress plugins

 / http://indiewebify.me / indiecert.net


* https://micro.blog/ -- good UI, user-focused. good!
* mastodon! (didn't exist when I started this project)
* BrowserID (aka Mozilla Persona)
* WebID (dead?)
* http://browserauth.net/

* https://www.digitalocean.com/community/tutorials/how-to-structure-large-flask-applications <----- kthx digitalocean :)
* ugh why http://fewstreet.com/2015/01/16/flask-blueprint-templates.html#Inspiration: petnames
# http://www.skyhunter.com/marcs/petnames/IntroPetNames.html
# this isn't quite a petnames system, but it does exploit:
# - linking keys to shorter names
# - storing the mappings decentralized
#

#Inspiration: petnames
# http://www.skyhunter.com/marcs/petnames/IntroPetNames.html
# this isn't quite a petnames system, but it does exploit:
# - linking keys to shorter names
# - storing the mappings decentralized
#




Static Site Generators
* https://github.com/getpelican/pelican/
* Jekyll??
 - comments in Jekyll:
   http://www.hezmatt.org/~mpalmer/blog/2011/07/19/static-comments-in-jekyll.html 
