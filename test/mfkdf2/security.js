/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')
const { hkdfSync } = require('crypto')
const speakeasy = require('speakeasy')

function xor (a, b) {
  const length = Math.max(a.length, b.length)
  const buffer = Buffer.alloc(length)

  for (let i = 0; i < length; ++i) {
    buffer[i] = a[i] ^ b[i]
  }

  return buffer
}

suite('mfkdf2/security', () => {
  suite('factor-fungibility', () => {
    test('correct', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        )
      )

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('incorrect', async () => {
      const setup = await mfkdf.policy.setup(
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        )
      )

      const derive = await mfkdf.policy.derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password2'),
          password2: mfkdf.derive.factors.password('password1')
        },
        false
      )

      derive.key.toString('hex').should.not.equal(setup.key.toString('hex'))
    })
  })

  suite('share-indistinguishability', () => {
    test('share-size', async () => {
      const secret = crypto.randomBytes(32)

      const shares1 = mfkdf.secrets.share(secret, 1, 3)
      shares1.should.have.length(3)
      for (const share of shares1) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares1.slice(0, 1).concat([null, null]), 1, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
      mfkdf.secrets
        .combine([null, null].concat(shares1.slice(2, 3)), 1, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))

      const shares2 = mfkdf.secrets.share(secret, 2, 3)
      shares2.should.have.length(3)
      for (const share of shares2) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares2.slice(0, 2).concat([null]), 2, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
      mfkdf.secrets
        .combine([null].concat(shares2.slice(1, 3)), 2, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))

      const shares3 = mfkdf.secrets.share(secret, 3, 3)
      shares3.should.have.length(3)
      for (const share of shares3) {
        share.should.have.length(32)
      }
      mfkdf.secrets
        .combine(shares3.slice(0, 3), 3, 3)
        .toString('hex')
        .should.equal(secret.toString('hex'))
    })
  })

  suite('share-encryption', () => {
    test('correct', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const materialp1 = await mfkdf.derive.factors.password('password1')(
        setup.policy.factors[0].params
      )
      const padp1 = Buffer.from(setup.policy.factors[0].pad, 'base64')
      const stretchedp1 = Buffer.from(
        hkdfSync(
          'sha256',
          materialp1.data,
          setup.policy.factors[0].salt,
          '',
          32
        )
      )
      const sharep1 = xor(padp1, stretchedp1)

      const derive = await mfkdf.policy.derive(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      await derive.recoverFactor(
        await mfkdf.setup.factors.password('newPassword1', { id: 'password1' })
      )
      const derive2f = await mfkdf.policy.derive(
        derive.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        false
      )
      derive2f.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      const derive2 = await mfkdf.policy.derive(derive.policy, {
        password1: mfkdf.derive.factors.password('newPassword1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))

      const materialp3 = await mfkdf.derive.factors.password('newPassword1')(
        derive.policy.factors[0].params
      )
      const padp3 = Buffer.from(derive.policy.factors[0].pad, 'base64')
      const stretchedp3 = Buffer.from(
        hkdfSync(
          'sha256',
          materialp3.data,
          derive.policy.factors[0].salt,
          '',
          32
        )
      )
      const sharep3 = xor(padp3, stretchedp3)

      await derive2.recoverFactor(
        await mfkdf.setup.factors.password('newPassword2', { id: 'password1' })
      )
      const derive3 = await mfkdf.policy.derive(derive2.policy, {
        password1: mfkdf.derive.factors.password('newPassword2'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive3.key.toString('hex').should.equal(setup.key.toString('hex'))

      sharep1.should.not.equal(sharep3)
    })
  })

  suite('factor-secret-encryption', () => {
    test('hotp', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.hotp({
          secret: Buffer.from('abcdefghijklmnopqrst')
        })
      ])

      const recover = xor(
        Buffer.from(setup.policy.factors[0].params.pad, 'base64'),
        Buffer.from('abcdefghijklmnopqrst')
      ).toString('hex')
      const key = setup.key.toString('hex').slice(0, recover.length)
      recover.should.not.equal(key)

      const derive1 = await mfkdf.derive.key(setup.policy, {
        hotp: mfkdf.derive.factors.hotp(241063)
      })

      setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    })
  })

  test('totp', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({
        secret: Buffer.from('abcdefghijklmnopqrst'),
        time: 1
      })
    ])

    const recover = xor(
      Buffer.from(setup.policy.factors[0].params.pad, 'base64'),
      Buffer.from('abcdefghijklmnopqrst')
    ).toString('hex')
    const key = setup.key.toString('hex').slice(0, recover.length)
    recover.should.not.equal(key)

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: mfkdf.derive.factors.totp(953265, { time: 1 })
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
  })

  suite('timing-oracle', () => {
    suite('totp/dynamic', async () => {
      test('no-oracle', async () => {
        const setup = await mfkdf.setup.key([await mfkdf.setup.factors.totp()])

        const code = parseInt(
          speakeasy.totp({
            secret: setup.outputs.totp.secret.toString('hex'),
            encoding: 'hex',
            step: setup.outputs.totp.period,
            algorithm: setup.outputs.totp.algorithm,
            digits: setup.outputs.totp.digits
          })
        )

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(code)
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(code)
        })

        const derive3 = await mfkdf.derive.key(derive2.policy, {
          totp: mfkdf.derive.factors.totp(code)
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('valid-fixed-oracle', async () => {
        const oracle = {}
        let date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 123456
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({ oracle })
        ])

        const code = parseInt(
          speakeasy.totp({
            secret: setup.outputs.totp.secret.toString('hex'),
            encoding: 'hex',
            step: setup.outputs.totp.period,
            algorithm: setup.outputs.totp.algorithm,
            digits: setup.outputs.totp.digits
          })
        )

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        const derive3 = await mfkdf.derive.key(derive2.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('invalid-fixed-oracle', async () => {
        const oracle = {}
        let date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 123456
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({ oracle })
        ])

        const code = parseInt(
          speakeasy.totp({
            secret: setup.outputs.totp.secret.toString('hex'),
            encoding: 'hex',
            step: setup.outputs.totp.period,
            algorithm: setup.outputs.totp.algorithm,
            digits: setup.outputs.totp.digits
          })
        )

        const oracle2 = {}
        date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle2[date] = 654321
          date += 30 * 1000 // 30 seconds
        }

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        const derive3 = await mfkdf.derive.key(derive2.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        derive1.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      })

      test('valid-dynamic-oracle', async () => {
        const oracle = {}
        let date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 100000 + i // unique code for each time
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({ oracle })
        ])

        const code = parseInt(
          speakeasy.totp({
            secret: setup.outputs.totp.secret.toString('hex'),
            encoding: 'hex',
            step: setup.outputs.totp.period,
            algorithm: setup.outputs.totp.algorithm,
            digits: setup.outputs.totp.digits
          })
        )

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        const derive3 = await mfkdf.derive.key(derive2.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle })
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('invalid-dynamic-oracle', async () => {
        const oracle = {}
        let date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 100000 + i // unique code for each time
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({ oracle })
        ])

        const code = parseInt(
          speakeasy.totp({
            secret: setup.outputs.totp.secret.toString('hex'),
            encoding: 'hex',
            step: setup.outputs.totp.period,
            algorithm: setup.outputs.totp.algorithm,
            digits: setup.outputs.totp.digits
          })
        )

        const oracle2 = {}
        date = Date.now()
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle2[date] = 654321
          date += 30 * 1000 // 30 seconds
        }

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        const derive3 = await mfkdf.derive.key(derive2.policy, {
          totp: mfkdf.derive.factors.totp(code, { oracle2 })
        })

        derive1.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      })
    })

    suite('totp/static', async () => {
      test('no-oracle', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('abcdefghijklmnopqrst'),
            time: 1
          })
        ])

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(953265, { time: 1 })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(241063, { time: 30001 })
        })

        const derive3 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(361687, { time: 60001 })
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('valid-fixed-oracle', async () => {
        const oracle = {}
        let date = 1
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 123456
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('abcdefghijklmnopqrst'),
            time: 1,
            oracle
          })
        ])

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(953265, {
            time: 1,
            oracle
          })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(241063, {
            time: 30001,
            oracle
          })
        })

        const derive3 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(361687, {
            time: 60001,
            oracle
          })
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('invalid-fixed-oracle', async () => {
        const oracle = {}
        let date = 1650430806597
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 123456
          date += 30 * 1000 // 30 seconds
        }

        const oracle2 = {}
        date = 1650430806597
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle2[date] = 654321
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('abcdefghijklmnopqrst'),
            time: 1650430806597,
            oracle
          })
        ])

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(528258, {
            time: 1650430943604,
            oracle: oracle2
          })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(99922, {
            time: 1650430991083,
            oracle: oracle2
          })
        })

        const derive3 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(398884, {
            time: 1650431018392,
            oracle: oracle2
          })
        })

        derive1.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      })

      test('valid-dynamic-oracle', async () => {
        const oracle = {}
        let date = 1
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 100000 + i // unique code for each time
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('abcdefghijklmnopqrst'),
            time: 1,
            oracle
          })
        ])

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(953265, {
            time: 1,
            oracle
          })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(241063, {
            time: 30001,
            oracle
          })
        })

        const derive3 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(361687, {
            time: 60001,
            oracle
          })
        })

        derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
      })

      test('invalid-dynamic-oracle', async () => {
        const oracle = {}
        let date = 1650430806597
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle[date] = 100000 + i // unique code for each time
          date += 30 * 1000 // 30 seconds
        }

        const oracle2 = {}
        date = 1650430806597
        date -= date % (30 * 1000) // round to the nearest 30 seconds
        for (let i = 0; i < 87600; i++) {
          oracle2[date] = 654321
          date += 30 * 1000 // 30 seconds
        }

        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.totp({
            secret: Buffer.from('abcdefghijklmnopqrst'),
            time: 1650430806597,
            oracle
          })
        ])

        const derive1 = await mfkdf.derive.key(setup.policy, {
          totp: mfkdf.derive.factors.totp(528258, {
            time: 1650430943604,
            oracle: oracle2
          })
        })

        const derive2 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(99922, {
            time: 1650430991083,
            oracle: oracle2
          })
        })

        const derive3 = await mfkdf.derive.key(derive1.policy, {
          totp: mfkdf.derive.factors.totp(398884, {
            time: 1650431018392,
            oracle: oracle2
          })
        })

        derive1.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive2.key.toString('hex').should.not.equal(setup.key.toString('hex'))
        derive3.key.toString('hex').should.not.equal(setup.key.toString('hex'))
      })
    })
  })

  suite('policy-integrity', () => {
    test('correct', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])
      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('invalid/$id', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      setup.policy.$id = 'invalid-id'

      await mfkdf.derive
        .key(
          setup.policy,
          {
            password1: mfkdf.derive.factors.password('password1'),
            password2: mfkdf.derive.factors.password('password2')
          },
          {},
          true
        )
        .should.be.rejectedWith(RangeError)
    })
  })
})
