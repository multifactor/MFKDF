## Adding Enveloped Secrets
In addition to performing [cryptographic operations]{@tutorial 09crypto} on detached ciphertexts, you can add enveloped secrets to a key. These secrets become part of the key policy, and travel with the key itself until they are removed. You can setup an enveloped secret like so:

```
// setup multi-factor derived key
const key = await mfkdf.setup.key([await mfkdf.setup.factors.password('password')])

// add enveloped secret to key
await key.addEnvelopedSecret('mySecret', Buffer.from('hello world'))
```

## Recovering Enveloped Secrets
Later, when you derive the key and wish to recover the enveloped secret, you can do so as follows:

```
// later... derive key
const derived = await mfkdf.derive.key(key.policy, { password: mfkdf.derive.factors.password('password') })

// retrieve secret
const secret = await derived.getEnvelopedSecret('mySecret')
secret.toString() // -> hello world
```

## Enveloped Keys
Sometimes, the secret you wish to envelop using a multi-factor derived key is itself a cryptographic key, such as an RSA private key. You can use {@link MFKDFDerivedKey.addEnvelopedKey} and {@link MFKDFDerivedKey.getEnvelopedKey} for this purpose:

```
// setup multi-factor derived key
const key = await mfkdf.setup.key([await mfkdf.setup.factors.password('password')])

// add enveloped rsa1024 key
await key.addEnvelopedKey('myKey', 'rsa1024')

// later... derive key
const derived = await mfkdf.derive.key(key.policy, { password: mfkdf.derive.factors.password('password') })

// retrieve enveloped key
const enveloped = await derived.getEnvelopedKey('myKey') // -> PrivateKeyObject
```
