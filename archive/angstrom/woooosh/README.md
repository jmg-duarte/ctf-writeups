---
title: "ångstromCTF 2020 - Woooosh Writeup"
date: 2020-03-19T8:44:29Z
---

For Woooosh we had a clicker game with an obfuscated clicker game.

![Woooosh](/ctf/angstrom/woooosh/wooooosh.png)

The backend [source](/ctf/angstrom/wooooosh/index.js) was given.
They used [`socket.io`](https://socket.io/), so we can do the same.

Looking at the source they use the first shape as the circle.

```js
if (dist(game.shapes[0].x, game.shapes[1].y, x, y) < 10) {
    game.score++;
}
```

So when we receive the generated shapes we just need to pick the first!

I opened a socket and started by emitting `start`.

```js
socket.emit("start");
```

Afterwards we just need to listen for events and reply.
Bellow is the clicking function.

```js
socket.on('shapes', shapes => {
    socket.emit("click", shapes[0].x, shapes[0].y);
});
```

And you'll need this to get the flag.

```js
socket.on('disp', disp => {
    console.log(disp);
});
```

Full source [here](/ctf/angstrom/woooosh/woooosh.js);