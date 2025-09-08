/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')

suite('examples', () => {
  suite('factors', () => {
    test('stack', async () => {
      // setup key with stack factor
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.stack([
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            }),
            await mfkdf.setup.factors.password('password2', {
              id: 'password2'
            })
          ]),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8 }
      )

      // derive key with stack factor
      const derive = await mfkdf.derive.key(setup.policy, {
        stack: mfkdf.derive.factors.stack({
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        }),
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('hmacsha1', async () => {
      // setup key with hmacsha1 factor
      const setup = await mfkdf.setup.key(
        [await mfkdf.setup.factors.hmacsha1()],
        { size: 8 }
      )

      // calculate response; could be done using hardware device
      const secret = setup.outputs.hmacsha1.secret
      const challenge = Buffer.from(
        setup.policy.factors[0].params.challenge,
        'hex'
      )
      const response = crypto
        .createHmac('sha1', secret)
        .update(challenge)
        .digest()

      // derive key with hmacsha1 factor
      const derive = await mfkdf.derive.key(setup.policy, {
        hmacsha1: mfkdf.derive.factors.hmacsha1(response)
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('totp', async () => {
      // setup key with totp factor
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('hello world'),
            time: 1650430806597
          })
        ],
        { size: 8 }
      )

      // derive key with totp factor
      const derive = await mfkdf.derive.key(setup.policy, {
        totp: mfkdf.derive.factors.totp(528258, { time: 1650430943604 })
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('hotp', async () => {
      // setup key with hotp factor
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.hotp({
            secret: Buffer.from('hello world')
          })
        ],
        { size: 8 }
      )

      // derive key with hotp factor
      const derive = await mfkdf.derive.key(setup.policy, {
        hotp: mfkdf.derive.factors.hotp(365287)
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('uuid', async () => {
      // setup key with uuid factor
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.uuid({
            uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
          })
        ],
        { size: 8 }
      )

      // derive key with uuid factor
      const derive = await mfkdf.derive.key(setup.policy, {
        uuid: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('question', async () => {
      // setup key with security question factor
      const setup = await mfkdf.setup.key(
        [await mfkdf.setup.factors.question('Fido')],
        { size: 8 }
      )

      // derive key with security question factor
      const derive = await mfkdf.derive.key(setup.policy, {
        question: mfkdf.derive.factors.question('Fido')
      })

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('ooba', async () => {
      // setup RSA key pair (on out-of-band server)
      const keyPair = await crypto.webcrypto.subtle.generateKey(
        {
          hash: 'SHA-256',
          modulusLength: 2048,
          name: 'RSA-OAEP',
          publicExponent: new Uint8Array([1, 0, 1])
        },
        true,
        ['encrypt', 'decrypt']
      )

      // setup key with out-of-band authentication factor
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.ooba({
          key: keyPair.publicKey,
          params: { email: 'test@mfkdf.com' }
        })
      ])

      // decrypt and send code (on out-of-band server)
      const next = setup.policy.factors[0].params.next
      const decrypted = await crypto.webcrypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        Buffer.from(next, 'hex')
      )
      const code = JSON.parse(Buffer.from(decrypted).toString()).code

      // derive key with out-of-band factor
      const derive = await mfkdf.derive.key(setup.policy, {
        ooba: mfkdf.derive.factors.ooba(code)
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('password', async () => {
      // setup key with password factor
      const setup = await mfkdf.setup.key(
        [await mfkdf.setup.factors.password('password')],
        { size: 8 }
      )

      // derive key with password factor
      const derive = await mfkdf.derive.key(setup.policy, {
        password: mfkdf.derive.factors.password('password')
      })

      setup.key.toString('hex') // -> 01d0c7236adf2516
      derive.key.toString('hex') // -> 01d0c7236adf2516

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })
  })

  test('setup/derive fast', async () => {
    // setup 16 byte 2-of-3-factor multi-factor derived key with a password, HOTP code, and UUID recovery code
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password'),
        await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
        await mfkdf.setup.factors.uuid({
          id: 'recovery',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        })
      ],
      { threshold: 2, size: 16 }
    )

    // derive key using 2 of the 3 factors
    const derive = await mfkdf.derive.key(setup.policy, {
      password: mfkdf.derive.factors.password('password'),
      hotp: mfkdf.derive.factors.hotp(365287)
    })

    setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
    derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771

    setup.key.toString('hex').should.equal(derive.key.toString('hex'))
  })

  test('setup/derive', async () => {
    // setup 16 byte 2-of-3-factor multi-factor derived key with a password, HOTP code, and UUID recovery code
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password'),
        await mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }),
        await mfkdf.setup.factors.uuid({
          id: 'recovery',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        })
      ],
      { threshold: 2, size: 16 }
    )

    // derive key using 2 of the 3 factors
    const derive = await mfkdf.derive.key(setup.policy, {
      password: mfkdf.derive.factors.password('password'),
      hotp: mfkdf.derive.factors.hotp(365287)
    })

    setup.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771
    derive.key.toString('hex') // -> 34d20ced439ec2f871c96ca377f25771

    setup.key.toString('hex').should.equal(derive.key.toString('hex'))
  })

  suite('secrets', () => {
    test('full', () => {
      // share secret using 2-of-3 shares
      const shares = mfkdf.secrets.share(Buffer.from('hello world'), 2, 3) // -> [Buffer, Buffer, Buffer]

      // recover secret using 2 shares
      const secret = mfkdf.secrets.combine([shares[0], null, shares[2]], 2, 3)
      secret.toString() // -> hello world

      // recover original 3 shares
      const recover = mfkdf.secrets.recover([shares[0], null, shares[2]], 2, 3) // -> [Buffer, Buffer, Buffer]

      recover.should.be.a('array')
    })
  })

  suite('policy', () => {
    test('validate', async () => {
      // setup key that can be derived from passwordA AND (passwordB OR passwordC)
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('passwordB', {
              id: 'passwordB'
            }),
            await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
          )
        )
      )

      // validate policy
      const valid = mfkdf.policy.validate(setup.policy) // -> true

      valid.should.be.true
    })

    test('ids', async () => {
      // setup key that can be derived from passwordA AND (passwordB OR passwordC)
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('passwordB', {
              id: 'passwordB'
            }),
            await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
          )
        )
      )

      // get list of ids
      const ids = mfkdf.policy.ids(setup.policy) // -> ['passwordA', 'passwordB', 'passwordC', ...]

      ids.includes('passwordA').should.be.true
      ids.includes('passwordB').should.be.true
      ids.includes('passwordC').should.be.true
    })

    test('evaluate', async () => {
      // setup key that can be derived from passwordA AND (passwordB OR passwordC)
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('passwordB', {
              id: 'passwordB'
            }),
            await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
          )
        )
      )

      // check if key can be derived with passwordA and passwordC
      const valid1 = await mfkdf.policy.evaluate(setup.policy, [
        'passwordA',
        'passwordC'
      ]) // -> true

      // check if key can be derived with passwordB and passwordC
      const valid2 = await mfkdf.policy.evaluate(setup.policy, [
        'passwordB',
        'passwordC'
      ]) // -> false

      valid1.should.be.true
      valid2.should.be.false
    })

    test('setup/derive', async () => {
      // setup key that can be derived from passwordA AND (passwordB OR passwordC)
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('passwordB', {
              id: 'passwordB'
            }),
            await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
          )
        ),
        { size: 8 }
      )

      // derive key with passwordA and passwordC (or passwordA and passwordB)
      const derive = await mfkdf.policy.derive(setup.policy, {
        passwordA: mfkdf.derive.factors.password('passwordA'),
        passwordC: mfkdf.derive.factors.password('passwordC')
      })

      setup.key.toString('hex') // -> e16a227944a65263
      derive.key.toString('hex') // -> e16a227944a65263

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('all', async () => {
      // setup key that can be derived from passwordA AND passwordB AND passwordC
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.all([
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
          await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
        ]),
        { size: 8 }
      )

      // derive key with passwordA and passwordB and passwordC
      const derive = await mfkdf.policy.derive(setup.policy, {
        passwordA: mfkdf.derive.factors.password('passwordA'),
        passwordB: mfkdf.derive.factors.password('passwordB'),
        passwordC: mfkdf.derive.factors.password('passwordC')
      })

      setup.key.toString('hex') // -> e16a227944a65263
      derive.key.toString('hex') // -> e16a227944a65263

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('any', async () => {
      // setup key that can be derived from passwordA OR passwordB OR passwordC
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
          await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
        ]),
        { size: 8 }
      )

      // derive key with passwordA (or passwordB or passwordC)
      const derive = await mfkdf.policy.derive(setup.policy, {
        passwordB: mfkdf.derive.factors.password('passwordB')
      })

      setup.key.toString('hex') // -> e16a227944a65263
      derive.key.toString('hex') // -> e16a227944a65263

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })

    test('atLeast2', async () => {
      // setup key that can be derived from at least 2 of (passwordA, passwordB, passwordC)
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('passwordA', { id: 'passwordA' }),
          await mfkdf.setup.factors.password('passwordB', { id: 'passwordB' }),
          await mfkdf.setup.factors.password('passwordC', { id: 'passwordC' })
        ]),
        { size: 8 }
      )

      // derive key with passwordA and passwordB (or passwordA and passwordC, or passwordB and passwordC)
      const derive = await mfkdf.policy.derive(setup.policy, {
        passwordA: mfkdf.derive.factors.password('passwordA'),
        passwordB: mfkdf.derive.factors.password('passwordB')
      })

      setup.key.toString('hex') // -> e16a227944a65263
      derive.key.toString('hex') // -> e16a227944a65263

      setup.key.toString('hex').should.equal(derive.key.toString('hex'))
    })
  })

  suite('reconstitution', () => {
    test('setThreshold', async () => {
      // setup 3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8 }
      )

      // change threshold to 2/3
      await setup.setThreshold(2)

      // derive key with 2 factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('removeFactor', async () => {
      // setup 2-of-3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8, threshold: 2 }
      )

      // remove one of the factors
      await setup.removeFactor('password2')

      // derive key with remaining 2 factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('removeFactors', async () => {
      // setup 1-of-3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8, threshold: 1 }
      )

      // remove two factors
      await setup.removeFactors(['password1', 'password2'])

      // derive key with remaining factor
      const derived = await mfkdf.derive.key(setup.policy, {
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('addFactor', async () => {
      // setup 2-of-3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8, threshold: 2 }
      )
      console.log(setup.policy)

      // add fourth factor
      await setup.addFactor(
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      )

      console.log(setup.policy)

      // derive key with any 2 factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password2: mfkdf.derive.factors.password('password2'),
        password4: mfkdf.derive.factors.password('password4')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('addFactors', async () => {
      // setup 2-of-3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8, threshold: 2 }
      )

      // add two more factors
      await setup.addFactors([
        await mfkdf.setup.factors.password('password4', { id: 'password4' }),
        await mfkdf.setup.factors.password('password5', { id: 'password5' })
      ])

      // derive key with any 2 factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password3: mfkdf.derive.factors.password('password3'),
        password5: mfkdf.derive.factors.password('password5')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('recoverFactor', async () => {
      // setup 3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8 }
      )

      // change the 2nd factor
      await setup.recoverFactor(
        await mfkdf.setup.factors.password('newPassword2', { id: 'password2' })
      )

      // derive key with new factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('newPassword2'),
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('recoverFactors', async () => {
      // setup 3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8 }
      )

      // change 2 factors
      await setup.recoverFactors([
        await mfkdf.setup.factors.password('newPassword2', { id: 'password2' }),
        await mfkdf.setup.factors.password('newPassword3', { id: 'password3' })
      ])

      // derive key with new factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('newPassword2'),
        password3: mfkdf.derive.factors.password('newPassword3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })

    test('reconstitute', async () => {
      // setup 2-of-3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8, threshold: 2 }
      )

      // remove 1 factor and add 1 new factor
      await setup.reconstitute(
        ['password1'], // remove
        [await mfkdf.setup.factors.password('password4', { id: 'password4' })] // add
      )

      // derive key with new factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })
  })

  suite('persistence', () => {
    test('persistence', async () => {
      // setup 3-factor multi-factor derived key
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { size: 8 }
      )

      // persist one of the factors
      const factor2 = setup.persistFactor('password2')

      // derive key with 2 factors
      const derived = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.persisted(factor2),
        password3: mfkdf.derive.factors.password('password3')
      })

      setup.key.toString('hex') // -> 64587f2a0e65dc3c
      derived.key.toString('hex') // -> 64587f2a0e65dc3c

      setup.key.toString('hex').should.equal(derived.key.toString('hex'))
    })
  })

  suite('crypto', () => {
    test('getSubkey', async () => {
      // setup multi-factor derived key
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password')
      ])

      // get sub-key for "eth"
      const subkey = key.getSubkey('eth')
      subkey.toString('hex') // -> 97cbb79f622ef8fcc86ab5e06fc0311377b1e59d6f43b0c24883c38fe8bcbac5
    })
  })
})
