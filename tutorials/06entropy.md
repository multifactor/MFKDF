## Basic Entropy Calculation

A multi-factor derived key is only as strong as its factors. For example, a 256-bit key based on a password is less secure than a 256-bit key based on a password AND an HOTP code, despite both being 256 bits. We use "bits of entropy" to quantify the security of a key, and provide a convenient way to measure it like so:

```
// password-only 256-bit key
const key1 = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour')
])
key1.entropyBits.real // -> 16.53929514807314

// password-and-hotp 256-bit key
const key2 = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour'),
  await mfkdf.setup.factors.hotp()
])
key2.entropyBits.real // -> 36.470863717397314
```

As the example above demonstrates, the password-only key has about 16 bits of real entropy, while the password-and-hotp key has about 36 bits of real entropy. We can now quantify that the password-and-hotp key is about 2<sup>20</sup> (or 1,048,576) times more secure than the password-only key. This aligns closely with our intuitive expectations, as an HOTP code has 10<sup>6</sup> (or 1,000,000) possibilities by default.

## Theoretical vs. Real Entropy

The library includes two measures of entropy: "theoretical" which is based on bit size alone, and "real" which is based on the actual complexity of things like passwords. We recommend using "real" for most practical purposes. Entropy is only provided on key setup and is not available on subsequent derivations.

```
const weak = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('abcdefgh')
])

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
])

const threshold = await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour', { id: 'password1' }),
  await mfkdf.setup.factors.uuid(),
  await mfkdf.setup.factors.password('abcdefgh', { id: 'password2' })
], { threshold: 2 })

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
