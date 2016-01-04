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
