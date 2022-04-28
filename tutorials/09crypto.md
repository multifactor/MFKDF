Now that you have derived a key, what can you do with it? Although you can use the key material provided by `derived.key` however you wish using 3rd-party crypto libraries, this library also includes some built-in cryptographic functions for encryption and digital signatures using highly standardized methods like AES and RSA.

## Encryption & Decryption
You can use a multi-factor derived key to encrypt secrets using a number of asymmetric algorithms like RSA1024 and RSA2048, and symmetric algorithms including DES, 3DES, AES128, AES192, AES256 (shown below):

```
// setup 3-factor multi-factor derived key
const key = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp(),
  await mfkdf.setup.factors.uuid()
])

// encrypt secret with derived key using AES-256
const encrypted = await key.encrypt('hello world', 'aes256')
```

When you want to decrypt the ciphertext to retrieve the original plaintext, you may do so like this:

```
// ... later, decrypt secret with derived key
const decrypted = await key.decrypt(encrypted, 'aes256')
decrypted.toString() // -> hello world
```

## Signing & Verification
You can also use a multi-factor derived key to encrypt secrets using RSA1024, RSA2048, or RSA3072. RSA1024, demonstrated below, is highly recommended for efficiency reasons:

```
// setup 3-factor multi-factor derived key
const key = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp(),
  await mfkdf.setup.factors.uuid()
])

// sign message with derived key using RSA-1024
const signature = await key.sign('hello world', 'rsa1024')

// verify signature
const valid = await key.verify('hello world', signature, 'rsa1024') // -> true
```
