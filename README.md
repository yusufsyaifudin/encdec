# ende

> Ende Regency is a regency on the island of Flores, within East Nusa Tenggara Province of Indonesia.
> 
> Source: [Wikipedia](https://en.wikipedia.org/wiki/Ende_Regency)

**EN**cryption **DE**cryption is a helper package to easily interact with encryption and decryption method in Golang.

Golang's native library of cryptography is complete, but we need to simplify the process.
For example, [RSA have limitation to encrypt long message](https://security.stackexchange.com/a/33445) 
and in Golang's lib function it only return bytes as output value. Bytes are useful when we want to transfer as binary
but, when using REST we may want to stringify it. So, this package will always return all encryption and decryption as string 
in Base64 format. 

Also, for RSA implementation, this package uses [Hybrid Crypto](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) implementation in Golang
to support RSA + AES.

## FAQ

### Why we use Base64 version of RSA keypair (RSA Public and Private key pair)?

RSA Public and Private key return long text with multiline. 
If we build Backend system which read configuration from environment variable (or Kubernetes ConfigMap),
we may have difficulties to copy and paste this long multiline text into environment variable.

To make public and private key easier to copy and paste, we need make it into one line, so we do Base64 encoding when generate key 
and decode it before use it.

### Why using base32 instead of base64?

Although Base32 representation takes roughly 20% more space than Base64, the resulting character set is all one case, and [some other advantages](https://en.wikipedia.org/wiki/Base32#Advantages).


