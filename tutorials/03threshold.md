## Setup Threshold-based Key

In the [multi-factor key derivation]{@tutorial 02mfkdf} tutorial, we set up a 3-factor multi-factor derived key using a password, an HOTP code, and a UUID. What if we want any 2 of these factors to be enough to derive the key? We can achieve this by setting `threshold:2` in the setup options like so:

```
// setup 16 byte 2-of-3 multi-factor derived key with a password, HOTP code, and UUID code
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('abcdefghijklmnopqrst') }),
  await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
], { size: 16, threshold: 2 })
setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

Behind the scenes, a secret sharing scheme such as Shamir's Secret Sharing is used to split the key into shares that can be derived using each factor, some threshold of which are required to retrieve the key.

## Derive Threshold-based Key

After setting up the above, 2-of-3 threshold multi-factor derived key, the key can later be derived using any 2 of the 3 established factors. For example, the key can be derived with the HOTP and UUID factors like so:

```
const derive = await mfkdf.derive.key(setup.policy, {
  hotp: mfkdf.derive.factors.hotp(241063),
  uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})
derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
```

## Suggested Uses

A common use case for threshold multi-factor key derivation is to facilitate factor recovery for users who forgot one or more of their factors. For example, in the password + HOTP + UUID key described above, the UUID factor can be used as a recovery code. The user can log in normally using their password + HOTP code. If their password is forgotten, they can still login using their HOTP code + UUID recovery code, and if their HOTP device is lost, they can still login using their password + UUID recovery code. While a 2-of-3 threshold is shown here, any desired threshold (eg. 3-of-5, 4-of-10) can be used.
