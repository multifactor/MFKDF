/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')

suite('factors/ooba', () => {
  test('full', async () => {
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

    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.ooba({
        key: keyPair.publicKey,
        params: {
          email: 'test@mfkdf.com'
        }
      })
    ])

    let next = setup.policy.factors[0].params.next
    let decrypted = await crypto.webcrypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      Buffer.from(next, 'hex')
    )
    let json = JSON.parse(Buffer.from(decrypted).toString())
    json.email.should.equal('test@mfkdf.com')
    let code = json.code

    const derive1 = await mfkdf.derive.key(setup.policy, {
      ooba: mfkdf.derive.factors.ooba(code)
    })

    next = derive1.policy.factors[0].params.next
    decrypted = await crypto.webcrypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      Buffer.from(next, 'hex')
    )
    json = JSON.parse(Buffer.from(decrypted).toString())
    json.email.should.equal('test@mfkdf.com')
    code = json.code

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      ooba: mfkdf.derive.factors.ooba(code.toLowerCase())
    })

    next = derive2.policy.factors[0].params.next
    decrypted = await crypto.webcrypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      Buffer.from(next, 'hex')
    )
    json = JSON.parse(Buffer.from(decrypted).toString())
    json.email.should.equal('test@mfkdf.com')
    code = json.code

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      ooba: mfkdf.derive.factors.ooba(code.toUpperCase())
    })

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  suite('errors', () => {
    test('derive', () => {
      (() => {
        mfkdf.derive.factors.ooba(12345)
      }).should.throw(TypeError)
    })

    test('setup', async () => {
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

      await mfkdf.setup.factors
        .ooba({
          id: 12345
        })
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup.factors
        .ooba({
          id: ''
        })
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup.factors
        .ooba({
          length: 'foo'
        })
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup.factors
        .ooba({
          length: 0
        })
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup.factors
        .ooba({
          length: 100
        })
        .should.be.rejectedWith(RangeError)

      await mfkdf.setup.factors
        .ooba({
          key: '12345'
        })
        .should.be.rejectedWith(TypeError)

      await mfkdf.setup.factors
        .ooba({
          key: keyPair.publicKey,
          params: '12345'
        })
        .should.be.rejectedWith(TypeError)
    })
  })
})
