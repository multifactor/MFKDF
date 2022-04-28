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
