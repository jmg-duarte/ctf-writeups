# GuessKey - *CTF 2021

This is a XOR encryption challenge,
in the easy one the original key was printed to the user.
Sending 0 would make the key stay the same instead of changing due to the XOR so guessing was just re-sending the key.

Without the key being printed at the beginning we try to bruteforce it to a given value,
in this case `2 ** 64 - 1`.

## Challenge

```python
from random import randint
import os
from flag import flag
N=64
key=randint(0,2**N)
# print key
key=bin(key)[2:].rjust(N,'0')
count=0
while True:
	p=0
	q=0
	new_key=''
	zeros=[0]
	for j in range(len(key)):
		if key[j]=='0':
			zeros.append(j)
	p=zeros[randint(0,len(zeros))-1]
	q=zeros[randint(0,len(zeros))-1]
	try:
		mask=int(raw_input("mask:"))
	except:
		exit(0)
	mask=bin(mask)[2:]
	if p>q:
		tmp=q
		q=p
		p=tmp
	cnt=0
	for j in range(0,N):
		if j in range(p,q+1):
			new_key+=str(int(mask[cnt])^int(key[j]))
		else:
			new_key+=key[j]
		cnt+=1
		cnt%=len(mask)
	key=new_key
	try:
		guess=int(raw_input("guess:"))
	except:
		exit(0)
	if guess==int(key,2):
		count+=1
		print 'Nice.'
	else:
		count=0
		print 'Oops.'
	if count>2:
		print flag
```

# Solution

```python
from pwn import *

N64 = 2 ** 64 - 1 # 64 bit integer with all bits set to 1
N63 = 2 ** 63 - 1 # 63 bit integer with all bits set to 1

p = process(["/usr/bin/python2", "./guesskey.py"])
success = 0
response = ""
attempt = 0
while True:
    print(f"attempt: {attempt}")
    attempt += 1
    maybe_flag = p.recvline() # receive "mask:\n" or "flag\n"
    if "flag" in maybe_flag.decode('utf-8'):
        print(maybe_flag)
        break
    p.sendline(str(N64))
    print(p.recvline()) # receive "guess:\n"
    if success % 2 == 0:
        p.sendline(str(N64))
    else:
        p.sendline(str(N63))
    response = p.recvline().decode('utf-8')
    if "Oo" not in response:
        success += 1
    if attempt > 300:
        break
```



