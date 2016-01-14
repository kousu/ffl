This is a simple 

Alternatives:
* `oauth-dropins <https://github.com/snarfed/oauth-dropins>`
* `python-social-auth <http://psa.matiasaguirre.net/>`

The latter is overengineered. It doesn't understand,
and you have to describe your flow as a list of callables written as strings,
which is all kiiiinds of fragile,
and the exact same list if executed for *all*
so in order to support facebook and twitter and all simultaneously you need to write code like
```
 if app == 'facebook': ...
 elif app == 'twitter': ...
```
and also it demands a persistence layer -- ie you pretty much have to already have a working, live, web app or it's useless

The former is pretty clean (I would tidy it further, drop .site_name() for example and make urlopen_access_token the default implementation for urlopen())
but it is tied to the Google App Engine and that's irritating.

My other goal here (forgive me for this) is to make OAuth look like OpenID;
for my use case I don't want to

also, this only supports OAuth2
OAuth1.0 has a critical session-fixation bug (which should have been obvious, but hindsight is 20/20) and so should never be used.
according to https://en.wikipedia.org/wiki/List_of_OAuth_providers, the only sites still on OAuth1.0a that I care about are Tumblr, Myspace and StatusNet)
 so i'll be happy just to get what I have


------

Setup
=====

Setting this up requires configuration. **I'M SORRY**. It's not my fault, it's OAuth's and the PKI infrastructure and the web being full of terrible things.

First, OAuth2 MUST run over TLS, which means you MUST have a cert handy.
So before you can actually try the code, you need to make up a cert.
You can use `../mkcert` to construct a self-signed one quickly, or `letsencrypt`.
If you use mkcert, make sure to import CA.crt into your browser certstore.

Right now the code is hard-coded to assume you're testing on https://localhost:5000
and have localhost.{crt,key} available. To create these, do
```
../mkcert #gen a CA
../mkcert localhost
rm CA.key CA.srl
```
if you tweak the code you can use other certs or other domains.
You need not only self-sign your local machine.
If you own domain.net and are testing on https://domain.net,
 you can self-sign with `../mkcert domain.net`, and your browser will accept the cert so long as you've imported `CA.crt`.


Second, you need app keys. First, rename `credentials.yml.example` to `credentials.yml`.
Then, for each provider, sign up for app keys.
This is different for each provider, and managing these is the most tedious piece of configuration.
Usually this means creating a developer account with the provider then finding the magic button buried in the settings that constructs an app.
An "app" consists of at least a friendly name, an ID and a "secret". The ID/secret is a username/password pair for authenticating the app to the provider.
 Some providers also demand that you tell them via their web UI what your callback URL is, or at least what domain you're planning to host on.
 You can usually fill in "localhost" here, for testing, but don't rely on it.

To find providers you can sign up, start with https://en.wikipedia.org/wiki/List_of_OAuth_providers
Any provider listed in credentials.yml which has a corresponding provider hook in the code
will be activated and listed on the WebUI.
(to see the full list of implemented providers do ....)

Plus *if you move servers* you will need to go and tell *each* OAuth provider your new address, because they generally whitelist what domains can go with each client app. Fuckers.

In theory, then you need to integrate the auth handler with the rest of your (web) app.
For now, just make sure you have python-Flask installed and do `./wedo.py`

You also need `/usr/share/dict/words` installed (for pseudoanon)

You also need to set up a VoIP provider and make the `./sms` script able to send messages if you want SMS auth.

Issues
------

OAuth and OpenID are vulnerable to phishing attacks, as <a href="http://identity.mozilla.com/post/7669886219/how-browserid-differs-from-openid">mozilla persona</a> points out;
namely: if you train people to type in their Facebook password after clicking a link from any random site, you train them to give it out without looking, from any random site.
Hm.

Persona sounds like a good idea, but it's dead in the water.
It promised separating the identity providers from what's being identified (the idea was it would get rolled into the browser as a part of the core javascript API)
but as far as I can tell, you still get lumped back to
Ugh
Why can't we just have this:
 an identity provider publishes a PGP key, and for each user it hosts signs the string "provider.com:username" with it
 when a user wants to authenticate somewhere, they present the signed token
 the server downloads the identity provider's public key (http://provider.com/auth/key.pem or something) (posssssibly with caching, tho caching has security implications)
 and checks the signature ..and then knows that provider.com vouches for username
 ???
