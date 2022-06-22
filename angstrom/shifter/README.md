---
title: "ångstromCTF 2020 - Shifter Writeup"
date: 2020-03-19T8:44:29Z
---

Connecting to Shifter we are greeted with the following:

```
Solve 50 of these epic problems in a row to prove you are a master crypto man like Aplet123!
You'll be given a number n and also a plaintext p.
Caesar shift `p` with the nth Fibonacci number.
n < 50, p is completely uppercase and alphabetic, len(p) < 50
You have 60 seconds!
--------------------
Shift BXRUJEAKBPSKTXDOXETQV by n=22
:
```

They give us a number `n` and a caesar cipher.
Easy enough, we can steal the implementations from StackOverflow (or write them ourselves) and do the following:

```py
def get_last_line(text):
    return text.split("\n")[-2]

def get_info(line):
    l = line.split(" ")
    return (l[1], l[-1].split("=")[1])
`
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        data = s.recv(1024)
        if not data:
            break
        text = data.decode("utf-8") 
        print(text)
        cipher, n = get_info(get_last_line(text))
        fN = fib(int(n))
        shifted = caesar(cipher, fN)
        print(shifted)
        s.sendall(bytes(shifted + '\n', 'utf-8'))
```

`fib` and `caesar` are the implementations for Fibonnaci and Caesar cipher, respectively, both taken from some place on the internet, hence not being shown.

Breaking the script down:

```py
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
```

The code above will connect us to the challenge, then we just need to receive the buffer and parse it.
I used these two functions:

```py
def get_last_line(text):
    return text.split("\n")[-2]

def get_info(line):
    l = line.split(" ")
    return (l[1], l[-1].split("=")[1])
```

Afterwards we just cast `n`, calculate it, and shift the given cipher.

Voilá!

```
actf{h0p3_y0u_us3d_th3_f0rmu14-1985098}
```