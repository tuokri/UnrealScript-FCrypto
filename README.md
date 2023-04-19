# FCrypto

UnrealScript cryptography utilities. The majority of this library
is based heavily on [BearSSL](https://www.bearssl.org/).

TODO: List other references/influences.

The "F" in FCrypto stands for my online username "fluudah" (lazy naming).

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

### Key Exchange

#### ECDH

Elliptic Curve Diffie-Hellman.

#### ECDHE

Elliptic Curve Diffie-Hellman Ephemeral.

#### Supported Elliptic Curves

##### Curve25519

### Symmetric Encryption

#### XXTEA

XXTEA with PKCS #7.

### Hash Functions

#### SHA-1

### Other (TODO)

#### HMAC

#### HKDF
