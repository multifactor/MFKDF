## Setup Policy-based Key
Policy-based key derivation combines [key stacking]{@tutorial 04stacking} and [threshold key derivation]{@tutorial 03threshold} behind the scenes to allow keys to be setup and derived using arbitrarily-complex policies combining a number of factors. Consider the following policy which requires (password1 OR password2) AND (password3 OR password4) using {@link policy.setup}:

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
After you setup a policy-based multi-factor derived key, you can use {@link policy.evaluate} to check which factor combinations could be used to derive the key:

```
// Check which factors can derive key
mfkdf.policy.evaluate(policy.policy, ['password1', 'password3']) // -> true
mfkdf.policy.evaluate(policy.policy, ['password3', 'password4']) // -> false
```

## Derive Policy-based Key
Later, you can derive the policy-based multi-factor key by providing a valid set of factors to {@link policy.derive} like so:

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

- {@link policy.or}
- {@link policy.and}
- {@link policy.all}
- {@link policy.any}
- {@link policy.atLeast}
