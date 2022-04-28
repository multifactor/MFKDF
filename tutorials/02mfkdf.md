## Setup Key
Before you can derive a multi-factor derived key, you must setup a "key policy," which is essentially just a [JSON document](https://mfkdf.com/schema/v1.0.0/policy.json) which specifies how a key is derived and ensures the key is the same every time (as long as the factors are correct). Setting up this policy yourself is difficult and potentially dangerous if insecure configuration options are chosen; therefore, the {@link setup.key} utility is provided with safe defaults. You can use it like so:

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

Setup returns an {@link MFKDFDerivedKey} object. Therefore, you can now access the derived key directly:

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

Derive also returns an {@link MFKDFDerivedKey} object. Therefore, you can again access the derived key directly like so:

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

| Factor | Setup | Derive |
| ------ | ----- | ------ |
| Password | {@link setup.factors.password} | {@link derive.factors.password} |
| UUID | {@link setup.factors.uuid} | {@link derive.factors.uuid} |
| HOTP | {@link setup.factors.hotp} | {@link derive.factors.hotp} |
| TOTP | {@link setup.factors.totp} | {@link derive.factors.totp} |
| HMAC-SHA1 | {@link setup.factors.hmacsha1} | {@link derive.factors.hmacsha1} |

Additionally, [persistence]{@tutorial 08persistence} and [stack]{@tutorial 04stacking} are special types of factors which can be used to modify how a key is derived.
