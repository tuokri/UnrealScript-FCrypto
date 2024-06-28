# FCrypto

UnrealScript cryptography utilities. The majority of this library
is based heavily on [BearSSL](https://www.bearssl.org/).

# DISCLAIMER: This library is under development and should be considered pre-alpha software!

#### Why BearSSL?

FCrypto is based on BearSSL simply because it is one of the most well documented
cryptography libraries I have studied. The code is extremely readable and has
helpful comments for both the API and the internals. The design choices and
implementation details with their rationale are extensively documented --
in and out of code. As UnrealScript is a C-like language (although not nearly
as low level as C), it is quite natural to port C code to UScript.
However, the number one reason for using BearSSL as a basis for my own UnrealScript
implementation was its i15 big integer implementation. It was the only big integer
reference implementation I could find that doesn't use any integer data types
wider than 32 bits. Since Unrealscript only has bytes and 32 bit (signed)
integer types, BearSSL's i15 implementation was perfect for
this use case. It is also possible there are other big integer implementations
that could have been easier to port into UnrealScript, and I just hadn't looked
hard enough. But in any case, BearSSL is the perfect learning tool from a
cryptography novice's perspective.

#### How secure is it?

Using FCrypto for any real production applications that transfer actual
critical/confidential data is not recommended. Any constant-time cryptography
guarantees of BearSSL could be lost in the porting process from C to
UnrealScript (not to mention bugs). FCrypto does not implement the entire
TLS suite. UnrealScript scripting engine is also a proprietary black box, so
it is hard to make any low level guarantees on what the script code actually does.
With that said, FCrypto is still probably more than secure (actually, probably
overkill) for all the video game server data transfer purposes of my personal
projects.

TODO: List other references/influences.

The "F" in FCrypto stands for my online username "fluudah" (yeah, lazy naming).

## Example Use Case

TODO: move/rename this section

1. ECDHE to exchange per-session keys (used for XXTEA).
2. ECDH to exchange static keys (used for HMAC).
3. Communicate application data.

## Features

### Big (Modular) Integers

UnrealScript big integer implementation based on
[BearSSL "i15" implementation](https://bearssl.org/bigint.html).

There are quite a many restrictions and details related to the
implementation, so reading BearSSL documentation on big integer
design is necessary if you plan on using this feature.

#### Implementation Notes

UnrealScript only has 32-bit integers, whereas BearSSL i15 big integers use
`uint16_t*` as the underlying type. This UScript implementation is therefore
essentially wasting half of the memory space. This should however be negligible
for any modern system running UE3 games or servers. For export, the integers
can be encoded into a byte array format that does not waste memory. Various
places in the code have additional checks to ensure the results are not altered,
notably when writing UScript 32-bit integers into (originally) 16-bit variables
in the BearSSL version e.g.:

```UnrealScript
X[V++] = Acc & 0xFFFF; // @ALIGN-32-16.
```

### Key Exchange

#### ECDH

Elliptic Curve Diffie-Hellman.

#### ECDHE

Elliptic Curve Diffie-Hellman Ephemeral.

#### Supported Elliptic Curves

##### Curve25519

### Symmetric Encryption

#### XXTEA

XXTEA with PKCS #7. Included in the library due to simplicity of the implementation.
XXTEA is theoretically vulnerable, but used for being lightweight and secure enough
for non-critical data.

### Hash Functions

#### SHA-1

### Other (TODO)

#### HMAC

#### HKDF

#### Development TODOs

Set up GitHub Actions builds with UDK-Lite. Check [uscript-msgbug](https://github.com/tuokri/uscript-msgbuf/)
for a reference on how to use UDK in CI builds.
