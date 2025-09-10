Key stacking allows a mulit-factor derived key to be used as an input to another multi-factor derived key, allowing for more complex key-derivation policies to be used.

Note: Using key stacking directly is not recommended; consider using the [key policy]{@tutorial 05policy} interface instead. However, if you wish to directly use stacking, you may do so as follows:

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
], { threshold: 1 })
setup.key.toString('hex') // -> 01d0c7236adf2516
```

See {@link setup.factors.stack} for more details.

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

See {@link derive.factors.stack} for more details.
