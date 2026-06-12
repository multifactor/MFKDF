import { expectType, expectError, expectAssignable } from 'tsd'
import * as mfkdf from '..'
import type {
  MFKDFFactor,
  MFKDFDerivedFactor,
  MFKDFFactorDerive,
  MFKDFFactorOutput,
  MFKDFFactorType,
  MFKDFFactorPolicy,
  StrengthFactorOutput,
  HOTPFactorOutput,
  TOTPFactorOutput,
  HashAlgorithm,
  MFKDFDerivedKey,
  MFKDFPolicy
} from '..'

// ===========================================================================
// setup.factors — each returns its specific factor variant (assignable to
// MFKDFFactor), discriminated on `type`.
// ===========================================================================
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.password('pw'))
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.password('pw', { id: 'p' }))
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.uuid())
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.uuid({ id: 'r', uuid: 'x' }))
expectAssignable<Promise<MFKDFFactor>>(
  mfkdf.setup.factors.hotp({ digits: 6, hash: 'sha1', secret: Buffer.from('x') })
)
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.totp({ step: 30, window: 1 }))
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.hmacsha1())
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.question('a', { question: 'q?' }))
expectAssignable<Promise<MFKDFFactor>>(mfkdf.setup.factors.passkey(Buffer.alloc(32)))

// hash option is a restricted union
expectError(mfkdf.setup.factors.hotp({ hash: 'md5' }))
// password requires a string argument
expectError(mfkdf.setup.factors.password(123))
// ooba requires its mandatory key + params
expectError(mfkdf.setup.factors.ooba({ length: 6 }))

// ===========================================================================
// setup.key
// ===========================================================================
const setupPromise = mfkdf.setup.key(
  [
    await mfkdf.setup.factors.password('pw', { id: 'p' }),
    await mfkdf.setup.factors.uuid({ id: 'r' })
  ],
  { threshold: 2, time: 0, memory: 0, integrity: true }
)
expectType<Promise<MFKDFDerivedKey>>(setupPromise)
const key = await setupPromise

// first argument must be an array of factors, not a single factor
expectError(mfkdf.setup.key(await mfkdf.setup.factors.password('pw')))
// unknown options are rejected
expectError(mfkdf.setup.key([], { bogus: true }))

// ===========================================================================
// MFKDFDerivedKey members
// ===========================================================================
expectType<Buffer>(key.key)
expectType<Buffer>(key.secret)
expectType<MFKDFPolicy>(key.policy)
expectType<Buffer[]>(key.shares)
expectType<Promise<Buffer>>(key.getSubkey('purpose', 'salt'))
expectType<Promise<Buffer>>(key.getSubkey())
expectType<Buffer>(key.persistFactor('p'))
expectType<Promise<void>>(key.setThreshold(2))
expectType<Promise<void>>(key.addFactor(await mfkdf.setup.factors.password('x', { id: 'x' })))
expectType<Promise<void>>(key.removeFactors(['p']))
expectType<Promise<void>>(key.reconstitute(['p'], [], 1))
expectType<Promise<void>>(key.strengthen(1, 1024))
expectType<Promise<string>>(key.derivePassword('purpose', 'salt', /[a-z]{6}/))
expectType<Promise<string>>(key.getHint('p'))
expectType<Promise<void>>(key.addHint('p', 7))
expectType<number | undefined>(key.entropyBits?.real)

// ===========================================================================
// derive.factors — each returns an MFKDFFactorDerive function
// ===========================================================================
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.password('pw'))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.uuid('uuid'))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.hotp(123456))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.totp(123456, { time: 0 }))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.persisted(Buffer.alloc(32)))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.hmacsha1(Buffer.alloc(20)))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.question('a'))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.ooba(123456))
expectType<MFKDFFactorDerive>(mfkdf.derive.factors.passkey(Buffer.alloc(32)))

// hotp expects a numeric code, not a string
expectError(mfkdf.derive.factors.hotp('123456'))

// ===========================================================================
// derive.key
// ===========================================================================
expectType<Promise<MFKDFDerivedKey>>(
  mfkdf.derive.key(key.policy, {
    password: mfkdf.derive.factors.password('pw')
  })
)
expectType<Promise<MFKDFDerivedKey>>(
  mfkdf.derive.key(key.policy, { password: mfkdf.derive.factors.password('pw') }, true)
)

// ===========================================================================
// secrets
// ===========================================================================
expectType<Buffer[]>(mfkdf.secrets.share(Buffer.from('s'), 2, 3))
expectType<Buffer>(mfkdf.secrets.combine([Buffer.alloc(1)], 2, 3))
expectType<Buffer>(mfkdf.secrets.recover([Buffer.alloc(1)], 2, 3))

// ===========================================================================
// policy
// ===========================================================================
expectType<boolean>(mfkdf.policy.validate(key.policy))
expectType<boolean>(mfkdf.policy.evaluate(key.policy, ['p']))
expectType<string[]>(mfkdf.policy.ids(key.policy))
expectType<Promise<MFKDFDerivedKey>>(mfkdf.policy.setup(await mfkdf.setup.factors.password('a', { id: 'a' })))

const f1 = await mfkdf.setup.factors.password('a', { id: 'a' })
const f2 = await mfkdf.setup.factors.password('b', { id: 'b' })
expectType<Promise<MFKDFFactor>>(mfkdf.policy.or(f1, f2))
expectType<Promise<MFKDFFactor>>(mfkdf.policy.and(f1, f2))
expectType<Promise<MFKDFFactor>>(mfkdf.policy.all([f1, f2]))
expectType<Promise<MFKDFFactor>>(mfkdf.policy.any([f1, f2]))
expectType<Promise<MFKDFFactor>>(mfkdf.policy.atLeast(1, [f1, f2]))

// ===========================================================================
// stage
// ===========================================================================
expectType<Promise<MFKDFFactor>>(
  mfkdf.stage.factor.setup(mfkdf.setup.factors.password('pw'))
)
expectType<Promise<MFKDFFactorDerive>>(
  mfkdf.stage.factor.derive(mfkdf.derive.factors.password('pw'), {})
)

// MFKDFDerivedKey is type-only: the class is never exported at runtime,
// so it must not be usable as a value (constructable / referenceable).
expectError(new mfkdf.MFKDFDerivedKey(key.policy, key.key, key.secret, [], []))
expectError(mfkdf.MFKDFDerivedKey)

// ===========================================================================
// MFKDFFactor shape — setup factors carry required id/entropy/output
// ===========================================================================
const factor = await mfkdf.setup.factors.password('pw')
expectType<'password'>(factor.type)
expectType<Buffer>(factor.data)
expectType<string>(factor.id)
expectType<number>(factor.entropy)
expectAssignable<MFKDFFactor>(factor)

// ===========================================================================
// Discriminated union: factor output() return narrows on factor type
// ===========================================================================
// Per-factor return types at the call site (no narrowing needed).
expectType<Promise<StrengthFactorOutput>>(factor.output())
expectType<Promise<HOTPFactorOutput>>((await mfkdf.setup.factors.hotp()).output())
expectType<Promise<TOTPFactorOutput>>((await mfkdf.setup.factors.totp()).output())
expectType<Promise<{ uuid: string }>>((await mfkdf.setup.factors.uuid()).output())
expectType<Promise<{ secret: Buffer }>>(
  (await mfkdf.setup.factors.hmacsha1()).output()
)
expectType<Promise<MFKDFDerivedKey>>(
  (
    await mfkdf.setup.factors.stack([
      await mfkdf.setup.factors.password('a', { id: 'a' })
    ])
  ).output()
)

// HOTP/TOTP output detail.
const otp = await (await mfkdf.setup.factors.hotp()).output()
expectType<'otpauth'>(otp.scheme)
expectType<string>(otp.uri)
expectType<HashAlgorithm>(otp.algorithm)
expectType<Buffer>(otp.secret)
expectType<number>(otp.counter)

// Narrowing a generic MFKDFFactor reveals the right output shape.
declare const anyFactor: MFKDFFactor
if (anyFactor.type === 'totp') {
  expectType<Promise<TOTPFactorOutput>>(anyFactor.output())
  expectType<number>((await anyFactor.output()).period)
}
if (anyFactor.type === 'uuid') {
  expectType<Promise<{ uuid: string }>>(anyFactor.output())
}
// TOTP output has `period`, HOTP has `counter` — not interchangeable.
expectError(otp.period)

// A partial/hand-built object is not a valid setup factor.
expectError<MFKDFFactor>({ type: 'password', data: Buffer.alloc(0) })
expectError(key.addFactor({ type: 'password', data: Buffer.alloc(0) }))

// Resolving a derive factor yields the leaner MFKDFDerivedFactor shape.
const derivedFactor = await mfkdf.derive.factors.password('pw')({})
expectType<MFKDFDerivedFactor>(derivedFactor)
expectType<MFKDFFactorType | 'persisted'>(derivedFactor.type)
expectType<Buffer>(derivedFactor.data)
// ...which has no id/entropy.
expectError(derivedFactor.id)
expectError(derivedFactor.entropy)
expectAssignable<MFKDFFactorOutput | undefined>(derivedFactor.output)

// ===========================================================================
// Discriminated union: policy factor entries narrow on `type`
// ===========================================================================
const entry: MFKDFFactorPolicy = key.policy.factors[0]
expectType<MFKDFFactorType>(entry.type)

if (entry.type === 'hotp') {
  expectType<number>(entry.params.digits)
  expectType<number>(entry.params.counter)
  expectType<HashAlgorithm>(entry.params.hash)
}
if (entry.type === 'totp') {
  expectType<string>(entry.params.offsets)
  expectType<number>(entry.params.window)
}
if (entry.type === 'question') {
  expectType<string | undefined>(entry.params.question)
}
if (entry.type === 'stack') {
  // a stacked factor embeds a full nested policy
  expectType<MFKDFFactorPolicy[]>(entry.params.factors)
}
// Fields from the wrong variant are not accessible without narrowing.
expectError(entry.params.digits)
