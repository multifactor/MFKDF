[![MFKDF](https://raw.githubusercontent.com/multifactor/MFKDF/master/site/logo.png "MFKDF")](https://mfkdf.com/ "MFKDF")

Multi-Factor Key Derivation Function

[![GitHub issues](https://img.shields.io/github/issues/multifactor/MFKDF)](https://github.com/multifactor/MFKDF/issues)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://www.mfkdf.com/coverage)
[![Tests](https://img.shields.io/badge/tests-100%25-brightgreen)](https://www.mfkdf.com/tests/mochawesome.html)
[![CC BY-NC-SA 4.0](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-brightgreen.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[![GitHub tag](https://img.shields.io/github/tag/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/tags)
[![GitHub release](https://img.shields.io/github/release/multifactor/MFKDF.svg)](https://github.com/multifactor/MFKDF/releases)
[![NPM release](https://img.shields.io/npm/v/mfkdf.svg)](https://www.npmjs.com/package/mfkdf)

[Site](https://mfkdf.com/) |
[Docs](https://mfkdf.com/docs/) |
[Demo](https://mfkdf.com/demo) |
[Videos](https://mfkdf.com/videos) |
[Contributing](https://github.com/multifactor/MFKDF/blob/master/CONTRIBUTING.md) |
[Security](https://github.com/multifactor/MFKDF/blob/master/SECURITY.md) |
[Multifactor](https://multifactor.com) |
[Paper](https://www.usenix.org/system/files/usenixsecurity23-nair-mfkdf.pdf) |
[Author](https://nair.me)

The Multi-Factor Key Derivation Function (MFKDF) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a password-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors, including HOTP, TOTP, and hardware tokens like YubiKey. MFKDF also enables self-service account recovery via K-of-N (secret-sharing style) key derivation, eliminating the need for central recovery keys, and supports arbitrarily complex key derivation policies.

###### Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Multi-Factor Key Derivation](#multi-factor-key-derivation)
  - [Threshold-based Key Derivation](#threshold-based-key-derivation)
  - [Key Stacking](#key-stacking)
  - [Policy-based Key Derivation](#policy-based-key-derivation)
  - [Entropy Estimation](#entropy-estimation)
  - [Factor Persistence](#factor-persistence)
- [Recovery & Reconstitution](#recovery--reconstitution)
- [Cryptographic Operations](#cryptographic-operations)
  - [Enveloped Secrets](#enveloped-secrets)
  - [Authentication using MFKDF](#authentication-using-mfkdf)

# Introduction

Password-based key derivation functions (eg. PBKDF2) are used to derive cryptographic keys from a password. Doing so allows users to encrypt secrets on the client side without having to worry about key management. But most users have notoriously insecure passwords, with up to 81% of them re-using passwords across multiple accounts. Even when multi-factor authentication is used to protect an account with a weak password, and password-derived keys are only as secure as the passwords they're based on.

The multi-factor key derivation function (MFKDF) improves upon password-based key derivation by using all of a user's authentication factors, not just their password, to derive a key. This library provides four key advantages over current password-based key derivation techniques:

1. Beyond passwords: supports deriving key material from a variety of common factors, including HOTP, TOTP, and hardware tokens like YubiKey.
2. Increased entropy: all factors must be simultaneously correct to derive a key, exponentially increasing the difficulty of brute-force attacks.
3. Self-service recovery: threshold keys can be used to recover lost factors on the client side without creating a centralized point of failure.
4. Authentication policies: multi-factor derived keys can cryptographically enforce arbitrarily complex authentication policies.

# Getting Started

## Download MFKDF.js

There are three ways to add `mfkdf.js` to your project: self-hosted, using a CDN, or using NPM (recommended).

### Option 1: Self-Hosted

First download the [latest release on GitHub](https://github.com/multifactor/MFKDF/releases), then add `mfkdf.js` or `mfkdf.min.js` to your page like so:

    <script src="mfkdf.min.js"></script>

### Option 2: CDN

You can automatically include the latest version of `mfkdf.min.js` in your page like so:

    <script src="https://cdn.jsdelivr.net/gh/multifactor/mfkdf/mfkdf.min.js"></script>

Note that this may automatically update to include breaking changes in the future. Therefore, it is recommended that you get the latest single-version tag with SRI from [jsDelivr](https://www.jsdelivr.com/package/npm/mfkdf) instead.

### Option 3: NPM (recommended)

Add MFKDF to your NPM project:

    npm install mfkdf

Require MFKDF like so:

    const mfkdf = require('mfkdf');

# Multi-Factor Key Derivation

## Setup Key

Before you can derive a multi-factor derived key, you must setup a "key policy," which is essentially just a [JSON document](https://mfkdf.com/schema/v1.0.0/policy.json) which specifies how a key is derived and ensures the key is the same every time (as long as the factors are correct). Setting up this policy yourself is difficult and potentially dangerous if insecure configuration options are chosen; therefore, the [setup.key](https://mfkdf.com/docs/setup.html#.key) utility is provided with safe defaults. You can use it like so:

```
// setup 16 byte 3-factor multi-factor derived key with a password, HOTP code, and UUID code
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
  await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
], { size: 16 })
```

Every factor in a multi-factor derived key must have a unique ID. If you use multiple factors of the same type, make sure to specify an ID like so:

```
const result = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour', { id: 'password1' }),
  await mfkdf.setup.factors.password('abcdefgh', { id: 'password2' })
], { size: 32 })
```

Setup returns an [MFKDFDerivedKey](https://mfkdf.com/docs/MFKDFDerivedKey.html) object. Therefore, you can now access the derived key directly:

```
setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Some of the factors you setup may have their own outputs at this stage. You can access them like so:

```
console.log(setup.outputs)
// -> {
//  password: { strength: { ... } },
//  hotp: { uri: 'otpauth://...', ... },
//  uuid: { uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' }
// }
```

You can also save the resulting key policy for later use like so:

```
// save key policy
const policy = JSON.stringify(setup.policy)
```

## Derive Key

Later, you can derive the same key using the saved key policy and established factors:

```
// derive key using the 3 factors
const derive = await mfkdf.derive.key(JSON.parse(policy), {
  password: mfkdf.derive.factors.password('password'),
  hotp: mfkdf.derive.factors.hotp(365287),
  uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})
```

Derive also returns an [MFKDFDerivedKey](https://mfkdf.com/docs/MFKDFDerivedKey.html) object. Therefore, you can again access the derived key directly like so:

```
// key should be the same if correct factors are provided
derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Some factors (like TOTP and HOTP) cause the key policy to change every time it is derived. Thus, don't forget to save the new key policy after deriving it:

```
// save new key policy
const newPolicy = JSON.stringify(derive.policy)
```

## Factors

The following basic MFKDF factors are currently supported:

| Factor    | Setup                                                                         | Derive                                                                          |
| --------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Password  | [setup.factors.password](https://mfkdf.com/docs/setup.factors.html#.password) | [derive.factors.password](https://mfkdf.com/docs/derive.factors.html#.password) |
| UUID      | [setup.factors.uuid](https://mfkdf.com/docs/setup.factors.html#.uuid)         | [derive.factors.uuid](https://mfkdf.com/docs/derive.factors.html#.uuid)         |
| HOTP      | [setup.factors.hotp](https://mfkdf.com/docs/setup.factors.html#.hotp)         | [derive.factors.hotp](https://mfkdf.com/docs/derive.factors.html#.hotp)         |
| TOTP      | [setup.factors.totp](https://mfkdf.com/docs/setup.factors.html#.totp)         | [derive.factors.totp](https://mfkdf.com/docs/derive.factors.html#.totp)         |
| HMAC-SHA1 | [setup.factors.hmacsha1](https://mfkdf.com/docs/setup.factors.html#.hmacsha1) | [derive.factors.hmacsha1](https://mfkdf.com/docs/derive.factors.html#.hmacsha1) |

Additionally, [persistence](#factor-persistence) and [stack](#key-stacking) are special types of factors which can be used to modify how a key is derived.

# Threshold-based Key Derivation

## Setup Threshold-based Key

In the [multi-factor key derivation](#multi-factor-key-derivation) tutorial, we set up a 3-factor multi-factor derived key using a password, an HOTP code, and a UUID. What if we want any 2 of these factors to be enough to derive the key? We can achieve this by setting `threshold:2` in the setup options like so:

```
// setup 16 byte 2-of-3 multi-factor derived key with a password, HOTP code, and UUID code
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
  await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
], { size: 16, threshold: 2 })
setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Behind the scenes, a secret sharing scheme such as Shamir's Secret Sharing is used to split the key into shares that can be derived using each factor, some threshold of which are required to retrieve the key.

## Derive Threshold-based Key

After setting up the above, 2-of-3 threshold multi-factor derived key, the key can later be derived using any 2 of the 3 established factors. For example, the key can be derived with the HOTP and UUID factors like so:

```
const derive = await mfkdf.derive.key(setup.policy, {
  hotp: mfkdf.derive.factors.hotp(365287),
  uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})
derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

## Suggested Uses

A common use case for threshold multi-factor key derivation is to facilitate factor recovery for users who forgot one or more of their factors. For example, in the password + HOTP + UUID key described above, the UUID factor can be used as a recovery code. The user can log in normally using their password + HOTP code. If their password is forgotten, they can still login using their HOTP code + UUID recovery code, and if their HOTP device is lost, they can still login using their password + UUID recovery code. While a 2-of-3 threshold is shown here, any desired threshold (eg. 3-of-5, 4-of-10) can be used.

# Key Stacking

Key stacking allows a mulit-factor derived key to be used as an input to another multi-factor derived key, allowing for more complex key-derivation policies to be used.

Note: Using key stacking directly is not recommended; consider using the [key policy](#policy-based-key-derivation) interface instead. However, if you wish to directly use stacking, you may do so as follows:

## Setup

The following key stacking setup has the effect of requiring (password1 AND password2) OR password3:

```
// setup key with stack factor
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.stack([
    await mfkdf.setup.factors.password('password1', { id: 'password1' }),
    await mfkdf.setup.factors.password('password2', { id: 'password2' })
  ]),
  await mfkdf.setup.factors.password('password3', { id: 'password3' })
], { size: 8, threshold: 1 })
setup.key.toString('hex') // -> 01d0c7236adf2516
```

See [setup.factors.stack](https://mfkdf.com/docs/setup.factors.html#.stack) for more details.

## Derivation

Using the above setup, the key can be derived using password1 and password2 like so:

```
// derive key with stack factor
const derive = await mfkdf.derive.key(setup.policy, {
  stack: mfkdf.derive.factors.stack({
    password1: mfkdf.derive.factors.password('password1'),
    password2: mfkdf.derive.factors.password('password2')
  })
})
derive.key.toString('hex') // -> 01d0c7236adf2516
```

See [derive.factors.stack](https://mfkdf.com/docs/derive.factors.html#.stack) for more details.

# Policy-based Key Derivation

## Setup Policy-based Key

Policy-based key derivation combines [key stacking](#key-stacking) and [threshold key derivation](#threshold-based-key-derivation) behind the scenes to allow keys to be setup and derived using arbitrarily-complex policies combining a number of factors. Consider the following policy which requires (password1 OR password2) AND (password3 OR password4) using [policy.setup](https://mfkdf.com/docs/policy.html#.setup):

```
// Setup policy-based multi-factor derived key
const policy = await mfkdf.policy.setup(
  await mfkdf.policy.and(
    await mfkdf.policy.or(
      await mfkdf.setup.factors.password('password1', { id: 'password1' }),
      await mfkdf.setup.factors.password('password2', { id: 'password2' })
    ),
    await mfkdf.policy.or(
      await mfkdf.setup.factors.password('password3', { id: 'password3' }),
      await mfkdf.setup.factors.password('password4', { id: 'password4' })
    )
  )
)
policy.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

## Evaluate Policy-based Key

After you setup a policy-based multi-factor derived key, you can use [policy.evaluate](https://mfkdf.com/docs/policy.html#.evaluate) to check which factor combinations could be used to derive the key:

```
// Check which factors can derive key
mfkdf.policy.evaluate(policy.policy, ['password1', 'password3']) // -> true
mfkdf.policy.evaluate(policy.policy, ['password3', 'password4']) // -> false
```

## Derive Policy-based Key

Later, you can derive the policy-based multi-factor key by providing a valid set of factors to [policy.derive](https://mfkdf.com/docs/policy.html#.derive) like so:

```
// Derive policy-based multi-factor derived key
const derived = await mfkdf.policy.derive(policy.policy, {
  password1: mfkdf.derive.factors.password('password1'),
  password4: mfkdf.derive.factors.password('password4')
})
derived.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

## Policy Logical Operators

The following logical operators can be used to construct a policy-based key:

- [policy.or](https://mfkdf.com/docs/policy.html#.or)
- [policy.and](https://mfkdf.com/docs/policy.html#.and)
- [policy.all](https://mfkdf.com/docs/policy.html#.all)
- [policy.any](https://mfkdf.com/docs/policy.html#.any)
- [policy.atLeast](https://mfkdf.com/docs/policy.html#.atLeast)

# Entropy Estimation

## Basic Entropy Calculation

A multi-factor derived key is only as strong as its factors. For example, a 256-bit key based on a password is less secure than a 256-bit key based on a password AND an HOTP code, despite both being 256 bits. We use "bits of entropy" to quantify the security of a key, and provide a convenient way to measure it like so:

```
// password-only 256-bit key
const key1 = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour')
], { size: 32 })
key1.entropyBits.real // -> 16.53929514807314

// password-and-hotp 256-bit key
const key2 = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour'),
  await mfkdf.setup.factors.hotp()
], { size: 32 })
key2.entropyBits.real // -> 36.470863717397314
```

As the example above demonstrates, the password-only key has about 16 bits of real entropy, while the password-and-hotp key has about 36 bits of real entropy. We can now quantify that the password-and-hotp key is about 2<sup>20</sup> (or 1,048,576) times more secure than the password-only key. This aligns closely with our intuitive expectations, as an HOTP code has 10<sup>6</sup> (or 1,000,000) possibilities by default.

## Theoretical vs. Real Entropy

The library includes two measures of entropy: "theoretical" which is based on bit size alone, and "real" which is based on the actual complexity of things like passwords. We recommend using "real" for most practical purposes. Entropy is only provided on key setup and is not available on subsequent derivations.

```
const weak = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('abcdefgh')
], { size: 32 })

// High theoretical entropy due to long password
weak.entropyBits.theoretical // -> 64

// Low real entropy due to weak password
weak.entropyBits.real // -> 5.044394119358453
```

## Entropy of Threshold Keys

When using threshold multi-factor derived keys, the entropy of your keys is only as strong as your weakest factors. Consider the following 3-of-3 and 2-of-3 multi-factor derived keys:

```
const all = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour', { id: 'password1' }),
  await mfkdf.setup.factors.uuid(),
  await mfkdf.setup.factors.password('abcdefgh', { id: 'password2' })
], { size: 32 })

const threshold = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour', { id: 'password1' }),
  await mfkdf.setup.factors.uuid(),
  await mfkdf.setup.factors.password('abcdefgh', { id: 'password2' })
], { size: 32, threshold: 2 })

all.entropyBits.real // -> 143.5836892674316
threshold.entropyBits.real // -> 21.583689267431595
```

The 2-of-3 key has significantly lower entropy than the 3-of-3 key, because it possibly could be derived without the strong UUID factor.

## Entropy of Policy-based Keys

Even when using a complex policy-based multi-factor derived key, the entropyBits calculation will be based on the weakest combination of factors permitted by the policy:

```
const policy = await mfkdf.policy.setup(
  await mfkdf.policy.and(
    await mfkdf.setup.factors.password('password1', { id: 'password1' }),
    await mfkdf.policy.and(
      await mfkdf.policy.or(
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ),
      await mfkdf.policy.and(
        await mfkdf.setup.factors.password('password4', { id: 'password4' }),
        await mfkdf.policy.or(
          await mfkdf.setup.factors.password('password5', { id: 'password5' }),
          await mfkdf.setup.factors.password('password6', { id: 'password6' })
        )
      )
    )
  )
)

policy.entropyBits.real // -> 45.27245744876085
```

# Recovery & Reconstitution

## Reconstitution Example

"Reconstitution" refers to the process of modifying the factors used to derive a key without changing the value of the derived key. Consider the following 3-factor derived key:

```
// setup 16 byte 3-factor multi-factor derived key with a password, HOTP code, and UUID code
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
  await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
], { size: 16 })
setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Let's say the user wishes to reset their password. The multi-factor derived key can be updated to reflect the new password like so:

```
// reconstitute key to change password
await setup.recoverFactor(await mfkdf.setup.factors.password('newPassword'))
```

The key can now be derived using the modified credentials:

```
// derive key using the 3 factors (including the new password)
const derive = await mfkdf.derive.key(setup.policy, {
  password: mfkdf.derive.factors.password('newPassword'),
  hotp: mfkdf.derive.factors.hotp(365287),
  uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})
derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Note that the key itself has not changed despite changing the factors; for example, secrets encrypted with the old key can still be decrypted with the new key (only the factors used to derive the key have changed).

## Reconstitution Functions

The following reconstitution functions can be used to modify a key's factors:

- [MFKDFDerivedKey.setThreshold](https://mfkdf.com/docs/MFKDFDerivedKey.html#.setThreshold)
- [MFKDFDerivedKey.removeFactor](https://mfkdf.com/docs/MFKDFDerivedKey.html#.removeFactor)
- [MFKDFDerivedKey.removeFactors](https://mfkdf.com/docs/MFKDFDerivedKey.html#.removeFactors)
- [MFKDFDerivedKey.addFactor](https://mfkdf.com/docs/MFKDFDerivedKey.html#.addFactor)
- [MFKDFDerivedKey.addFactors](https://mfkdf.com/docs/MFKDFDerivedKey.html#.addFactors)
- [MFKDFDerivedKey.recoverFactor](https://mfkdf.com/docs/MFKDFDerivedKey.html#.recoverFactor)
- [MFKDFDerivedKey.recoverFactors](https://mfkdf.com/docs/MFKDFDerivedKey.html#.recoverFactors)
- [MFKDFDerivedKey.reconstitute](https://mfkdf.com/docs/MFKDFDerivedKey.html#.reconstitute)

# Factor Persistence

Persistence allows you to save one or more of the factors used to setup a multi-factor derived key (eg. as browser cookies) so that they do not need to be used to derive the key in the future. Consider the following 3-factor multi-factor derived key:

```
// setup 3-factor multi-factor derived key
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password1', { id: 'password1' }),
  await mfkdf.setup.factors.password('password2', { id: 'password2' }),
  await mfkdf.setup.factors.password('password3', { id: 'password3' })
], { size: 8 })
setup.key.toString('hex') // -> 64587f2a0e65dc3c
```

Let's say that we don't want a user to need factor \#2 the next time they login. We can directly save the key material corresponding to this factor like so:

```
// persist one of the factors
const factor2 = setup.persistFactor('password2')
```

When later deriving the key, the stored material can be used in place of the factor:

```
// derive key with 2 factors
const derived = await mfkdf.derive.key(setup.policy, {
  password1: mfkdf.derive.factors.password('password1'),
  password2: mfkdf.derive.factors.persisted(factor2),
  password3: mfkdf.derive.factors.password('password3')
})
derived.key.toString('hex') // -> 64587f2a0e65dc3c
```

One suggested use case for this technique is allowing a user to bypass their 2nd authentication factor when using a trusted device by persisting the material for that factor as a cookie on their browser.

# Cryptographic Operations

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

# Enveloped Secrets

## Adding Enveloped Secrets

In addition to performing [cryptographic operations](#cryptographic-operations) on detached ciphertexts, you can add enveloped secrets to a key. These secrets become part of the key policy, and travel with the key itself until they are removed. You can setup an enveloped secret like so:

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

Sometimes, the secret you wish to envelop using a multi-factor derived key is itself a cryptographic key, such as an RSA private key. You can use [MFKDFDerivedKey.addEnvelopedKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.addEnvelopedKey) and [MFKDFDerivedKey.getEnvelopedKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.getEnvelopedKey) for this purpose:

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

# Authentication using MFKDF

## Introduction

A major advantage of using multi-factor derived keys is the ability for user data to remain protected by all of their authentication factors even if central authentication servers are compromised by an attacker, as keys are derived entirely on the client side. This purpose is defeated if authentication factors (eg. an HOTP key) must be stored on the server for verification. Therefore, it is suggested that the multi-factor derived key itself be used for user authentication. Because the multi-factor derived key cannot be obtained without presenting a valid combination of factors according to the key policy, using the key to authenticate serves as proof that a valid set of factors has been presented by the user.

## Authentication Protocols

This library supports a number of standardized key-based authentication protocols which can be used to securely authenticate a user based on their multi-factor derived key. The protocols included are summarized below:

| Name                                       | Cryptography | Freshness | Prove                                                                                                                     | Verify                                                                                                                     | Key                                                                                       |
| ------------------------------------------ | ------------ | --------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| ISO 9798 2-Pass Unilateral Auth            | Symmetric    | Challenge | [ISO97982PassUnilateralAuthSymmetric](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97982PassUnilateralAuthSymmetric)   | [VerifyISO97982PassUnilateralAuthSymmetric](https://mfkdf.com/docs/auth.html#.VerifyISO97982PassUnilateralAuthSymmetric)   | [ISO9798SymmetricKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798SymmetricKey)   |
| ISO 9798 Public-Key 2-Pass Unilateral Auth | Asymmetric   | Challenge | [ISO97982PassUnilateralAuthAsymmetric](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97982PassUnilateralAuthAsymmetric) | [VerifyISO97982PassUnilateralAuthAsymmetric](https://mfkdf.com/docs/auth.html#.VerifyISO97982PassUnilateralAuthAsymmetric) | [ISO9798AsymmetricKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798AsymmetricKey) |
| ISO 9798 2-Pass Unilateral Auth over CCF   | Hash         | Challenge | [ISO97982PassUnilateralAuthCCF](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97982PassUnilateralAuthCCF)               | [VerifyISO97982PassUnilateralAuthCCF](https://mfkdf.com/docs/auth.html#.VerifyISO97982PassUnilateralAuthCCF)               | [ISO9798CCFKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798CCFKey)               |
| ISO 9798 1-Pass Unilateral Auth            | Symmetric    | Timestamp | [ISO97981PassUnilateralAuthSymmetric](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97981PassUnilateralAuthSymmetric)   | [VerifyISO97981PassUnilateralAuthSymmetric](https://mfkdf.com/docs/auth.html#.VerifyISO97981PassUnilateralAuthSymmetric)   | [ISO9798SymmetricKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798SymmetricKey)   |
| ISO 9798 Public-Key 1-Pass Unilateral Auth | Asymmetric   | Timestamp | [ISO97981PassUnilateralAuthAsymmetric](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97981PassUnilateralAuthAsymmetric) | [VerifyISO97981PassUnilateralAuthAsymmetric](https://mfkdf.com/docs/auth.html#.VerifyISO97981PassUnilateralAuthAsymmetric) | [ISO9798AsymmetricKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798AsymmetricKey) |
| ISO 9798 1-Pass Unilateral Auth over CCF   | Hash         | Timestamp | [ISO97981PassUnilateralAuthCCF](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO97981PassUnilateralAuthCCF)               | [VerifyISO97981PassUnilateralAuthCCF](https://mfkdf.com/docs/auth.html#.VerifyISO97981PassUnilateralAuthCCF)               | [ISO9798CCFKey](https://mfkdf.com/docs/MFKDFDerivedKey.html#.ISO9798CCFKey)               |

## Authentication Example

The following example uses ISO 9798 2-Pass Unilateral Auth:

```
// setup multi-factor derived key
const key = await mfkdf.setup.key([await mfkdf.setup.factors.password('password')])

// challenger: create random challenge
const challenge = crypto.randomBytes(32)
const identity = Buffer.from('Challenger')

// responder: generate response
const response = await key.ISO97982PassUnilateralAuthSymmetric(challenge, identity)

// verifier: verify response
const authKey = await key.ISO9798SymmetricKey()
const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, response, authKey) // -> true
```

Each of the supported authentication protocols has its own dedicated example, so please check the documentation for each protocol if you feel another protocol is a better fit for your project.

For more information on any of the functions described above, please view the MFKDF [website](https://mfkdf.com) and [documentation](https://mfkdf.com/docs/).

Copyright ©2021-2025 Multifactor, Inc.
