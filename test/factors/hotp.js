/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('factors/hotp', () => {
  test('size', async () => {
    mfkdf.setup.factors
      .hotp({
        secret: Buffer.from('hello world')
      })
      .should.throw()
  })

  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.hotp({
        secret: Buffer.from('abcdefghijklmnopqrst')
      })
    ])

    const derive1 = await mfkdf.derive.key(setup.policy, {
      hotp: mfkdf.derive.factors.hotp(241063)
    })

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      hotp: mfkdf.derive.factors.hotp(361687)
    })

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      hotp: mfkdf.derive.factors.hotp(979122)
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    derive1.key.toString('hex').should.equal(derive2.key.toString('hex'))
    derive2.key.toString('hex').should.equal(derive3.key.toString('hex'))
  })

  test('defaults', async () => {
    await mfkdf.setup.key([await mfkdf.setup.factors.hotp()])
  })

  suite('errors', async () => {
    test('code/type', async () => {
      (() => {
        mfkdf.derive.factors.hotp('hello')
      }).should.throw(TypeError)
    })

    test('id/type', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: 12345
        })
        .should.be.rejectedWith(TypeError)
    })

    test('id/range', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: ''
        })
        .should.be.rejectedWith(RangeError)
    })

    test('digits/type', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('digits/low', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 4
        })
        .should.be.rejectedWith(RangeError)
    })

    test('digits/high', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 9
        })
        .should.be.rejectedWith(RangeError)
    })

    test('hash/range', async () => {
      await mfkdf.setup.factors
        .hotp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          hash: 'sha123'
        })
        .should.be.rejectedWith(RangeError)
    })

    test('secret/type', async () => {
      mfkdf.setup.factors
        .hotp({
          secret: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })
  })
})
