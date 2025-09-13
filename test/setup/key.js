/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()
const Ajv = require('ajv')
const ajv = new Ajv()
const policySchema = require('../../site/mfkdf2/public/schema/v2.0.0/policy.json')

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('setup/key', () => {
  test('default', async () => {
    const key = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('hello')
    ])
    ajv.validate(policySchema, key.policy).should.be.true
  })

  suite('id', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello')
      ])
      policy.$id.should.be.a('string')
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [await mfkdf.setup.factors.password('hello')],
        { id: 'hello-world' }
      )
      policy.$id.should.equal('hello-world')
    })

    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { id: 12345 })
        .should.be.rejectedWith(TypeError)
    })

    test('invalid/range', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { id: '' })
        .should.be.rejectedWith(RangeError)
    })
  })

  suite('threshold', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello', { id: 'password1' }),
        await mfkdf.setup.factors.password('hello', { id: 'password2' })
      ])
      policy.threshold.should.equal(2)
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('hello', { id: 'password1' }),
          await mfkdf.setup.factors.password('hello', { id: 'password2' })
        ],
        { threshold: 1 }
      )
      policy.threshold.should.equal(1)
    })

    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], {
          threshold: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('invalid/range', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { threshold: 0 })
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { threshold: 2 })
        .should.be.rejectedWith(RangeError)
    })
  })

  suite('salt', () => {
    test('default', async () => {
      const { policy } = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('hello')
      ])
      const salt = Buffer.from(policy.salt, 'base64')
      salt.length.should.equal(32)
    })

    test('valid', async () => {
      const { policy } = await mfkdf.setup.key(
        [await mfkdf.setup.factors.password('hello')],
        { salt: Buffer.from('1234567812345678', 'base64') }
      )
      policy.salt.should.equal('1234567812345678')
    })

    test('invalid/type', async () => {
      await mfkdf.setup
        .key([await mfkdf.setup.factors.password('hello')], { salt: 'hello' })
        .should.be.rejectedWith(TypeError)
    })
  })

  suite('factors', () => {
    test('valid', async () => {
      await mfkdf.setup.key([
        {
          type: 'password',
          id: 'password',
          data: Buffer.from('password', 'utf-8'),
          params: async () => {
            return {}
          },
          output: async () => {
            return {}
          }
        }
      ])
    })

    test('id', async () => {
      await mfkdf.setup
        .key([
          await mfkdf.setup.factors.password('hello', { id: 'password1' }),
          await mfkdf.setup.factors.password('hello', { id: 'password1' })
        ])
        .should.be.rejectedWith(RangeError)
    })

    test('invalid/type', async () => {
      await mfkdf.setup.key('hello').should.be.rejectedWith(TypeError)

      await mfkdf.setup
        .key([
          {
            type: 12345,
            id: 'password',
            data: Buffer.from('password', 'utf-8'),
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup
        .key([
          {
            type: 'password',
            id: 12345,
            data: Buffer.from('password', 'utf-8'),
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup
        .key([
          {
            type: 'password',
            id: 'password',
            data: 12345,
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup
        .key([
          {
            type: 'password',
            id: 'password',
            data: Buffer.from('password', 'utf-8'),
            params: 12345
          }
        ])
        .should.be.rejectedWith(TypeError)
    })

    test('invalid/range', async () => {
      await mfkdf.setup.key([]).should.be.rejectedWith(RangeError)

      await mfkdf.setup
        .key([
          {
            type: '',
            id: 'password',
            data: Buffer.from('password', 'utf-8'),
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup
        .key([
          {
            type: 'password',
            id: '',
            data: Buffer.from('password', 'utf-8'),
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup
        .key([
          {
            type: 'password',
            id: 'password',
            data: Buffer.from('', 'utf-8'),
            params: async () => {
              return {}
            }
          }
        ])
        .should.be.rejectedWith(RangeError)
    })
  })
})
