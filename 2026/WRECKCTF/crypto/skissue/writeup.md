# crypto/skissue Writeup
Author: freed | 38 solves | 181 points | Difficulty: Medium  
**TLDR: Factor a 2048-bit semiprime with OSINT techniques**
## Description
```
Don't get skissued
```
The challenge consists of `output.txt`, a file containing values for RSA encryption, and `gen.py`, a source file explaining how output.txt was generated.
## Solve
In `gen.py`, two 1024-bit primes are generated as `p` and `q` before they are used to encrypt the contents of `flag.txt`. The primes and encryption values are printed to the user before the encryption values without the original primes are written to `output.txt`.  
A 2048-bit semiprime was too large to factor in a reasonable time with any known classical algorithm, so I looked for any issues for how the prime was generated. But due to how simple and minimal the code was, I didn't think that there would be any vulnerabilities to exploit with the code itself.  
This is when I remembered from an LA CTF challenge author who told me about how LA CTF crypto challenges generate the primes on a per-connection basis to prevent bad actors from uploading the factorizations to FactorDB and giving away the challenge, FactorDB being a website where numbers with known factorizations are posed on.   
So I decided to look up the prime on FactorDB to find that it did have a factorization. To confirm that this was the intended solution, I checked the metadata on FactorDB to find that it was uploaded before the WRECKCTF began, so I was pretty sure this was the intended solution.  
## Script
```
from Crypto.Util.number import long_to_bytes

# From FactorDB
p = 1242 ... 4127
q = 1332 ... 1171

# From output.txt
c = 7208 ... 9944

n = p*q
e = 65537

t = (p-1)*(q-1)
d = pow(e,-1,t)
m = long_to_bytes(pow(c,d,n))
print(m)
```
**Flag:** `wreck{n0_sk1ll_1ssu3}`