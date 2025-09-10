## Reconstitution Example

"Reconstitution" refers to the process of modifying the factors used to derive a key without changing the value of the derived key. Consider the following 3-factor derived key:

```
// setup 16 byte 3-factor multi-factor derived key with a password, HOTP code, and UUID code
const setup = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('password'),
  await mfkdf.setup.factors.hotp({ secret: Buffer.from('abcdefghijklmnopqrst') }),
  await mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
])
setup.key.toString('hex') // -> 34d2…5771
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
  hotp: mfkdf.derive.factors.hotp(241063),
  uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})
derive.key.toString('hex') // -> 34d2…5771
```

Note that the key itself has not changed despite changing the factors; for example, secrets encrypted with the old key can still be decrypted with the new key (only the factors used to derive the key have changed).

## Reconstitution Functions

The following reconstitution functions can be used to modify a key's factors:

- {@link MFKDFDerivedKey.setThreshold}
- {@link MFKDFDerivedKey.removeFactor}
- {@link MFKDFDerivedKey.removeFactors}
- {@link MFKDFDerivedKey.addFactor}
- {@link MFKDFDerivedKey.addFactors}
- {@link MFKDFDerivedKey.recoverFactor}
- {@link MFKDFDerivedKey.recoverFactors}
- {@link MFKDFDerivedKey.reconstitute}
