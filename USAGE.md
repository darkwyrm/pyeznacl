# Using PyEZNaCl

## Concepts: CryptoString

One of the many challenges with working with encryption is that keys and hashes are arbitrary-looking binary blobs of data -- they have zero meaning to people just looking at them. They also lack context or any other descriptive information; a 256-bit BLAKE2B hash looks the same as a SHA256 hash, but Heaven help you if you get something mixed up.

The solution is to represent keys and hashes as text and pair an algorithm nametag with the text representation of the key or hash. For example, a sample 128-bit BLAKE2B hash in its binary form is represented in hex as `a6 30 2a b0 da ef 14 fb 9b 82 b9 69 3e 78 76 6b`. Without spaces, this is 32 characters. The same hash can be represented in CryptoString format as `BLAKE2B-128:rZ6h7+V2$mn}WG%K6rL(`.

The format consists of the prefix, a colon for the separator, and the Base85-encoded binary data. Base85 was chosen because of its higher efficiency and source. The prefix consists of up to 24 characters, which may be capital ASCII letters, numbers, or dashes. A colon is used to separate the prefix from the encoded data.

The official prefixes as of this writing are:

- ED25519
- CURVE25519
- AES-128 / AES-256 / AES-384 / AES-512
- SALSA20 / XSALSA20
- SHA-256 / SHA-384 / SHA-512
- SHA3-256 / SHA3-384 / SHA3-512
- BLAKE2B-128 / BLAKE2B-256 / BLAKE2B-512
- BLAKE3-128 / BLAKE3-256 / BLAKE3-512

Regular usage of a CryptoString mostly involves creating an instance from other data. The constructor can take a CryptoString-formatted string or a string prefix and some raw bytes. Once data has been put into the instance, getting it back out is just a matter of casting to a string, or calling `as_string()`, `as_bytes()`, or `as_raw()`. The last of these three methods only returns the raw data stored in the object.

```python
from pyeznacl import CryptoString

key = nacl.public.PrivateKey.generate()
my_public_key = CryptoString('CURVE25519', key.public_key.encode())
my_private_key = CryptoString('CURVE25519', key.encode())

print(f"My new public key is {my_public_key}")
```

The methods `set()`, `set_raw()`, and `is_valid()` are also useful. The module also comes with a bare function `is_cryptostring()` which returns True if a string passed to it is CryptoString-formatted.

## Error Handling

Many functions and methods used in this module use the RetVal module. RetVal is essentially a dictionary used for returning multiple values dynamically, easier error checking without using exceptions, and richer error information while debugging.

## Encryption and Decryption

The encryption and decryption API is designed to be as simple as possible. This still means, however, that you have to be careful how to apply it. Creating a new encryption key pair and encrypting (or decrypting) a section of text with it is a simple as the following:

```python
from pyeznacl import EncryptionPair

encpair = EncryptionPair()
status = encpair.encrypt(b'This is some text')

if status.error():
	print('An error occurred while encrypting')

encrypted_data = status['data']
print(f"Encryption type: {status['prefix']}")
print(f"Encrypted data: {encrypted_data})")

status = encpair.decrypt(encrypted_data)
if status.error():
	print('An error occurred while decrypting')
print(f"Decrypted data: {status['data']}")
```

When encrypting, two fields are returned: `prefix`, which describes the type of encryption, and `data`, which holds the Base85-encoded encrypted data.

Two caveats: data encrypted/decrypted must fit within system memory, and the `SecretKey` class should be used for encrypting/decrypting large amounts of data for performance reasons -- asymmetric cryptography is slow.

These classes have other methods for getting the keys themselves, hashes of the encoded versions of the keys and saving them to a JSON file. Separate functions will load keys from these files, as well, such as `load_encryptionpair`.

## Cryptographic Signing

Signing and verifying are just as easy as encryption and decryption. To avoid confusion with encryption keys, the class for verifying with the public half of a signing key pair is called `VerificationKey`. `SigningPair` operates with the same concepts as `EncryptionPair` except using the methods `sign()` and `verify()`. Signatures generated using these classes are returned as `CryptoString` objects.

```python
from pyeznacl import SigningPair, CryptoString

signpair = SigningPair()
status = signpair.sign(b'This is some text')

if status.error():
	print('An error occurred while signing')

signature = CryptoString(status['signature'])
print(f"Signature type: {signature.prefix}")
print(f"Signature: {signature.data})")

status = signpair.verify(b'This is some text', signature)
if status.error():
	print('An error occurred while verifying')
else:
	print('Successfully verified signature')
```

## Hashes

Getting a hash of a piece of data is intended to be as simple as possible. All PyEZNaCl hash functions return a CryptoString-formatted string.

```python
from pyeznacl import sha256hash, blake2hash

print(blake2hash(b'This is some text'))
print(sha256hash(b'This is some text'))
```

Four 256-bit algorithms are provided by the library: BLAKE2B, BLAKE3, SHA2, and SHA3 using the functions `blake2hash()`, `blake3hash()`, `sha256hash()`, and `sha3_256hash()`. `hashfile` is also provided for easy file hashing with large file support.

## Passwords

Like encryption, password handling is often tricky. The `Password` class provides an easy-to-use API for working with passwords. The Argon2id hashing algorithm is used internally by PyNaCl for generating the hashes. Here is a sample usage:

```python
import sys

from pyeznacl import Password

pwd = Password()

for p in [ 'foobar', 'ALittle1', 'MyS3cretPassw*rd']:
	status = pwd.set(p)	
	print(f"'{p}' is a {status['strength']} password")

status = pwd.set('MyS3cretPassw*rd')
if status.error():
	print(f"There was an error setting the password: {status.error()}")
	sys.exit(1)

guess = input('Try to guess the password: ')
match = pwd.check(guess)
if match:
	print('You guessed right!')
else:
	print('You guessed wrong. Better luck next time')
```
