/**
 * Type definitions for MFKDF (Multi-Factor Key Derivation Function) v2.
 *
 * These declarations are hand-written to mirror the JSDoc-annotated public API
 * in src/. Consumers need `@types/node` available for the global `Buffer` type.
 *
 * @see https://mfkdf.com
 */

/// <reference types="node" />

export = mfkdf
export as namespace mfkdf

declare namespace mfkdf {
  // ===========================================================================
  // Core types
  // ===========================================================================

  /** Async function returning a factor's public parameters. */
  type MFKDFFactorParams = (
    config: { key: Buffer }
  ) => Promise<Record<string, unknown>>

  /** Async function returning a factor's output (generic/derive side). */
  type MFKDFFactorOutput = () => Promise<Record<string, unknown>>

  /** `output()` of a password or security-question factor. */
  interface StrengthFactorOutput {
    /** zxcvbn strength estimate of the input. */
    strength: Record<string, unknown>
  }
  /** `output()` of a HOTP factor — provisioning details for the authenticator. */
  interface HOTPFactorOutput {
    scheme: 'otpauth'
    type: 'hotp'
    label: string
    secret: Buffer
    issuer: string
    algorithm: HashAlgorithm
    digits: number
    counter: number
    uri: string
  }
  /** `output()` of a TOTP factor — provisioning details for the authenticator. */
  interface TOTPFactorOutput {
    scheme: 'otpauth'
    type: 'totp'
    label: string
    secret: Buffer
    issuer: string
    algorithm: HashAlgorithm
    digits: number
    period: number
    uri: string
  }

  /** Fields shared by every setup-produced factor. */
  interface MFKDFFactorBase {
    /** Unique identifier of this factor. */
    id: string
    /** Key material for this factor. */
    data: Buffer
    /** Asynchronous function to fetch the public parameters for this factor. */
    params: MFKDFFactorParams
    /** Actual bits of entropy this factor provides. */
    entropy: number
  }

  interface PasswordFactor extends MFKDFFactorBase {
    type: 'password'
    output: () => Promise<StrengthFactorOutput>
  }
  interface QuestionFactor extends MFKDFFactorBase {
    type: 'question'
    output: () => Promise<StrengthFactorOutput>
  }
  interface UUIDFactor extends MFKDFFactorBase {
    type: 'uuid'
    output: () => Promise<{ uuid: string }>
  }
  interface PasskeyFactor extends MFKDFFactorBase {
    type: 'passkey'
    output: () => Promise<Record<string, never>>
  }
  interface OOBAFactor extends MFKDFFactorBase {
    type: 'ooba'
    output: () => Promise<Record<string, never>>
  }
  interface HMACSHA1Factor extends MFKDFFactorBase {
    type: 'hmacsha1'
    output: () => Promise<{ secret: Buffer }>
  }
  interface HOTPFactor extends MFKDFFactorBase {
    type: 'hotp'
    output: () => Promise<HOTPFactorOutput>
  }
  interface TOTPFactor extends MFKDFFactorBase {
    type: 'totp'
    output: () => Promise<TOTPFactorOutput>
  }
  interface StackFactor extends MFKDFFactorBase {
    type: 'stack'
    /** A stacked factor's output is the nested derived key. */
    output: () => Promise<MFKDFDerivedKey>
  }

  /**
   * A factor produced by `setup.factors.*` or a `policy` combinator and
   * consumed by `setup.key` / `addFactor` / `recoverFactor`. Discriminated on
   * `type`: narrowing reveals the precise `output()` return for that factor
   * (e.g. an `otpauth` object for HOTP/TOTP, `{ strength }` for password).
   */
  type MFKDFFactor =
    | PasswordFactor
    | QuestionFactor
    | UUIDFactor
    | PasskeyFactor
    | OOBAFactor
    | HMACSHA1Factor
    | HOTPFactor
    | TOTPFactor
    | StackFactor

  /**
   * The factor object obtained by resolving a derive-side function. Unlike a
   * setup {@link MFKDFFactor} it carries no id or entropy estimate, and the
   * `persisted` factor has no output.
   */
  interface MFKDFDerivedFactor {
    /** Includes `'persisted'` in addition to the standard factor types. */
    type: MFKDFFactorType | 'persisted'
    data: Buffer
    params: MFKDFFactorParams
    /** Absent for the `persisted` factor. */
    output?: MFKDFFactorOutput
  }

  /**
   * A derive-side factor: an async function which, given the policy's factor
   * config, resolves to the {@link MFKDFDerivedFactor} used to reconstruct the
   * key.
   */
  type MFKDFFactorDerive = (
    config: Record<string, unknown>
  ) => Promise<MFKDFDerivedFactor>

  /** Hash algorithm accepted by the HOTP/TOTP factors. */
  type HashAlgorithm = 'sha1' | 'sha256' | 'sha512'

  /** The `type` tag shared by every factor and policy entry. */
  type MFKDFFactorType =
    | 'password'
    | 'uuid'
    | 'passkey'
    | 'question'
    | 'hotp'
    | 'totp'
    | 'hmacsha1'
    | 'ooba'
    | 'stack'

  /** Fields common to every policy factor entry. */
  interface MFKDFFactorPolicyBase {
    /** Unique identifier of this factor within the policy. */
    id: string
    /** Encrypted pad (base64). */
    pad?: string
    /** Encrypted factor secret (base64). */
    secret?: string
    /** Per-factor salt (base64). */
    salt?: string
    /** Optional low-entropy hint stored for this factor. */
    hint?: string
  }

  interface PasswordFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'password'
    params: Record<string, never>
  }
  interface UUIDFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'uuid'
    params: Record<string, never>
  }
  interface PasskeyFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'passkey'
    params: Record<string, never>
  }
  interface QuestionFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'question'
    params: { question?: string }
  }
  interface HOTPFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'hotp'
    params: {
      hash: HashAlgorithm
      digits: number
      pad: string
      counter: number
      offset: number
    }
  }
  interface TOTPFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'totp'
    params: {
      start: number
      hash: HashAlgorithm
      digits: number
      step: number
      window: number
      pad: string
      offsets: string
    }
  }
  interface HMACSHA1FactorPolicy extends MFKDFFactorPolicyBase {
    type: 'hmacsha1'
    params: { challenge: string; pad: string }
  }
  interface OOBAFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'ooba'
    params: {
      length: number
      /** Exported JWK of the out-of-band channel public key. */
      key: Record<string, unknown>
      params: Record<string, unknown>
      /** Next encrypted code (hex). */
      next: string
      pad: string
    }
  }
  interface StackFactorPolicy extends MFKDFFactorPolicyBase {
    type: 'stack'
    /** A stacked factor embeds a full nested policy as its params. */
    params: MFKDFPolicy
  }

  /**
   * A single factor entry within a key policy. Discriminated on `type`: narrow
   * with `if (factor.type === 'hotp') { factor.params.digits }`.
   */
  type MFKDFFactorPolicy =
    | PasswordFactorPolicy
    | UUIDFactorPolicy
    | PasskeyFactorPolicy
    | QuestionFactorPolicy
    | HOTPFactorPolicy
    | TOTPFactorPolicy
    | HMACSHA1FactorPolicy
    | OOBAFactorPolicy
    | StackFactorPolicy

  /** A serializable key policy describing how a key is derived. */
  interface MFKDFPolicy {
    $schema?: string
    $id?: string
    threshold?: number
    salt?: string
    hmac?: string
    kdf?: Record<string, unknown>
    factors: MFKDFFactorPolicy[]
    [key: string]: unknown
  }

  /** Entropy estimate (in bits) for a derived key. */
  interface MFKDFEntropyBits {
    theoretical: number
    real: number
  }

  // ===========================================================================
  // MFKDFDerivedKey class
  // ===========================================================================

  /**
   * A multi-factor derived key and the operations available on it.
   *
   * Instances are only ever produced by the library (`setup.key`,
   * `derive.key`, `policy.setup`, `policy.derive`) — the constructor is not
   * exported, so this is declared as an interface rather than a class.
   */
  interface MFKDFDerivedKey {
    /** The policy used to derive this key. */
    policy: MFKDFPolicy
    /** The value of this derived key. */
    key: Buffer
    /** The secret (pre-KDF) value of this derived key. */
    secret: Buffer
    /** The shares corresponding to the factors of this key. */
    shares: Buffer[]
    /** The outputs corresponding to the factors of this key. */
    outputs: Array<Record<string, unknown>>
    /** Entropy estimate for this key. Present only on keys produced by setup. */
    entropyBits?: MFKDFEntropyBits

    // --- Crypto ---
    /** Derive a sub-key from this key for a given purpose/salt. */
    getSubkey(purpose?: string, salt?: string): Promise<Buffer>

    // --- Reconstitution ---
    /** Change the number of factors required to derive this key. */
    setThreshold(threshold: number): Promise<void>
    /** Remove an existing factor by id. */
    removeFactor(id: string): Promise<void>
    /** Remove several existing factors by id. */
    removeFactors(ids: string[]): Promise<void>
    /** Add a new factor to this key. */
    addFactor(factor: MFKDFFactor): Promise<void>
    /** Add several new factors to this key. */
    addFactors(factors: MFKDFFactor[]): Promise<void>
    /** Replace (recover) an existing factor with a new one. */
    recoverFactor(factor: MFKDFFactor): Promise<void>
    /** Replace (recover) several existing factors. */
    recoverFactors(factors: MFKDFFactor[]): Promise<void>
    /** Add/remove factors and/or adjust the threshold in one operation. */
    reconstitute(
      removeFactors?: string[],
      addFactors?: MFKDFFactor[],
      threshold?: number
    ): Promise<void>

    // --- Persistence ---
    /** Persist a factor, returning the share that can be used to bypass it. */
    persistFactor(id: string): Buffer

    // --- Strengthening ---
    /** Add additional argon2 time/memory cost to this key. */
    strengthen(time?: number, memory?: number): Promise<void>

    // --- Multi-factor derived password generation (MFDPG) ---
    /** Derive a deterministic password matching the given regex policy. */
    derivePassword(purpose: string, salt: string, regex: RegExp): Promise<string>

    // --- Hints ---
    /** Compute a hint (low-entropy prefix) for a factor without storing it. */
    getHint(factor: string, bits?: number): Promise<string>
    /** Compute and store a hint for a factor in the policy. */
    addHint(factor: string, bits?: number): Promise<void>
  }

  // ===========================================================================
  // setup
  // ===========================================================================

  namespace setup {
    interface KeyOptions {
      /** Unique identifier for this key; random UUIDv4 by default. */
      id?: string
      /** Number of factors required to derive key; all by default. */
      threshold?: number
      /** Cryptographic salt; securely generated by default. */
      salt?: Buffer
      /** Whether to sign the resulting key policy (recommended). */
      integrity?: boolean
      /** Additional rounds of argon2 time cost to add; 0 by default. */
      time?: number
      /** Additional argon2 memory cost to add (in KiB); 0 by default. */
      memory?: number
    }

    /** Validate and set up a configuration for a multi-factor derived key. */
    function key(
      factors: MFKDFFactor[],
      options?: KeyOptions
    ): Promise<MFKDFDerivedKey>

    namespace factors {
      interface PasswordOptions {
        id?: string
      }
      function password(
        password: string,
        options?: PasswordOptions
      ): Promise<PasswordFactor>

      interface UUIDOptions {
        /** UUID to use; random v4 UUID by default. */
        uuid?: string
        id?: string
      }
      function uuid(options?: UUIDOptions): Promise<UUIDFactor>

      interface HOTPOptions {
        id?: string
        hash?: HashAlgorithm
        digits?: number
        secret?: Buffer
        issuer?: string
        label?: string
      }
      function hotp(options?: HOTPOptions): Promise<HOTPFactor>

      interface TOTPOptions {
        id?: string
        hash?: HashAlgorithm
        digits?: number
        secret?: Buffer
        issuer?: string
        label?: string
        /** Current time for TOTP; defaults to Date.now(). */
        time?: number
        /** Max window between logins, in steps (1 month by default). */
        window?: number
        /** TOTP step size. */
        step?: number
        /** Timing oracle offsets to use; none by default. */
        oracle?: Record<string, unknown>
      }
      function totp(options?: TOTPOptions): Promise<TOTPFactor>

      interface StackOptions {
        id?: string
        threshold?: number
        salt?: Buffer
      }
      function stack(
        factors: MFKDFFactor[],
        options?: StackOptions
      ): Promise<StackFactor>

      interface HMACSHA1Options {
        id?: string
        secret?: Buffer
      }
      function hmacsha1(options?: HMACSHA1Options): Promise<HMACSHA1Factor>

      interface QuestionOptions {
        /** Security question corresponding to this factor. */
        question?: string
        id?: string
      }
      function question(
        answer: string,
        options?: QuestionOptions
      ): Promise<QuestionFactor>

      interface OOBAOptions {
        id?: string
        /** Number of characters to use in one-time codes. */
        length?: number
        /** Public key of out-of-band channel. */
        key: CryptoKey
        /** Parameters to provide to the out-of-band channel. */
        params: Record<string, unknown>
      }
      function ooba(options: OOBAOptions): Promise<OOBAFactor>

      interface PasskeyOptions {
        id?: string
      }
      /** Derive a factor from a 256-bit WebAuthn PRF secret. */
      function passkey(
        secret: Buffer,
        options?: PasskeyOptions
      ): Promise<PasskeyFactor>
    }
  }

  // ===========================================================================
  // derive
  // ===========================================================================

  namespace derive {
    /** Derive a key from a policy and the supplied factors. */
    function key(
      policy: MFKDFPolicy,
      factors: Record<string, MFKDFFactorDerive>,
      verify?: boolean
    ): Promise<MFKDFDerivedKey>

    namespace factors {
      function password(password: string): MFKDFFactorDerive
      function uuid(uuid: string): MFKDFFactorDerive
      function hotp(code: number): MFKDFFactorDerive
      function totp(
        code: number,
        options?: { time?: number; oracle?: Record<string, unknown> }
      ): MFKDFFactorDerive
      function stack(
        factors: Record<string, MFKDFFactorDerive>
      ): MFKDFFactorDerive
      /** Bypass a factor using its persisted share. */
      function persisted(share: Buffer): MFKDFFactorDerive
      function hmacsha1(response: Buffer): MFKDFFactorDerive
      function question(answer: string): MFKDFFactorDerive
      function ooba(code: number): MFKDFFactorDerive
      function passkey(secret: Buffer): MFKDFFactorDerive
    }
  }

  // ===========================================================================
  // secrets (Shamir secret sharing)
  // ===========================================================================

  namespace secrets {
    /** Split a secret into `n` shares, `k` of which are required. */
    function share(secret: Buffer, k: number, n: number): Buffer[]
    /** Combine `k`-of-`n` shares back into the original secret. */
    function combine(shares: Buffer[], k: number, n: number): Buffer
    /** Recover the original secret from a set of shares. */
    function recover(shares: Buffer[], k: number, n: number): Buffer
  }

  // ===========================================================================
  // policy (logic combinators & validation)
  // ===========================================================================

  namespace policy {
    interface SetupOptions {
      id?: string
      threshold?: number
      salt?: Buffer
    }
    /** Set up a key from a single (possibly composite) factor. */
    function setup(
      factor: MFKDFFactor,
      options?: SetupOptions
    ): Promise<MFKDFDerivedKey>

    /** Derive a key from a policy using logic-combinator factors. */
    function derive(
      policy: MFKDFPolicy,
      factors: Record<string, MFKDFFactorDerive>,
      verify?: boolean
    ): Promise<MFKDFDerivedKey>

    /** Determine whether a key can be derived from the given factor ids. */
    function evaluate(policy: MFKDFPolicy, factors: string[]): boolean
    /** List the factor ids declared in a policy. */
    function ids(policy: MFKDFPolicy): string[]
    /** Validate that a policy is well-formed. */
    function validate(policy: MFKDFPolicy): boolean

    /** Factor satisfiable by either input factor. */
    function or(factor1: MFKDFFactor, factor2: MFKDFFactor): Promise<MFKDFFactor>
    /** Factor satisfiable only by both input factors. */
    function and(factor1: MFKDFFactor, factor2: MFKDFFactor): Promise<MFKDFFactor>
    /** Factor satisfiable only by all input factors. */
    function all(factors: MFKDFFactor[]): Promise<MFKDFFactor>
    /** Factor satisfiable by any one of the input factors. */
    function any(factors: MFKDFFactor[]): Promise<MFKDFFactor>
    /** Factor satisfiable by at least `n` of the input factors. */
    function atLeast(n: number, factors: MFKDFFactor[]): Promise<MFKDFFactor>
  }

  // ===========================================================================
  // stage (pre-computation helpers)
  // ===========================================================================

  namespace stage {
    interface FactorStage {
      /** Pre-compute the params/outputs of a setup factor. */
      setup(factor: Promise<MFKDFFactor>, key?: Buffer): Promise<MFKDFFactor>
      /** Pre-compute the outputs of a derive factor. */
      derive(
        factor: MFKDFFactorDerive,
        params: Record<string, unknown>,
        key?: Buffer
      ): Promise<MFKDFFactorDerive>
    }
    const factor: FactorStage
  }
}
