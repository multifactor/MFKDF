/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

const crypto = require('crypto')

suite('factors/hmacsha1', () => {
  test('hmacsha1', async () => {
    const key = Buffer.from('e60ab41d81d5494a90593d484d68f676a60a2450', 'hex')
    const challenge = Buffer.from('hello')

    const res = crypto.createHmac('sha1', key).update(challenge).digest('hex')

    const real = '1292826fd25cdc59e5f83d3e11aa561610562875'

    res.should.equal(real)
  })

  test('dynamic', async () => {
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.hmacsha1()])

    const secret = setup.outputs.hmacsha1.secret
    const challenge1 = Buffer.from(
      setup.policy.factors[0].params.challenge,
      'hex'
    )

    const response1 = crypto
      .createHmac('sha1', secret)
      .update(challenge1)
      .digest()

    const derive1 = await mfkdf.derive.key(setup.policy, {
      hmacsha1: mfkdf.derive.factors.hmacsha1(response1)
    })

    const challenge2 = Buffer.from(
      derive1.policy.factors[0].params.challenge,
      'hex'
    )
    const response2 = crypto
      .createHmac('sha1', secret)
      .update(challenge2)
      .digest()

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      hmacsha1: mfkdf.derive.factors.hmacsha1(response2)
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive2.key.toString('hex'))
  })

  test('static', async () => {
    const setup =
      '{"$schema":"https://mfkdf.com/schema/v2.0.0/policy.json","$id":"8b6874f7-5dbb-4196-bc89-347cd6b02dc6","size":32,"threshold":1,"salt":"nhh2/3AwOf2r2n7uRONoM697IjEKsHfAeyo8NxF1G94=","kdf":{"type":"argon2id","params":{"rounds":2,"memory":24576,"parallelism":1}},"factors":[{"id":"hmacsha1","type":"hmacsha1","pad":"PsS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","salt":"PsS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","params":{"challenge":"5a5f71c3a584b797d3c8f7d0f59653a2234781b06f2540df42946aa380f634a3430e6aad294e392543cc4ecd3da039bfa8041b179d14afd360a104e3354f01dd","pad":"f8d33204be0436f2629d5173e9bd3fc1953cf982"}}]}'

    const derive = await mfkdf.derive.key(JSON.parse(setup), {
      hmacsha1: mfkdf.derive.factors.hmacsha1(
        Buffer.from('0f09b8c89bfefdbc4909432685358eca79912b6a', 'hex')
      )
    })

    derive.key
      .toString('hex')
      .should.equal(
        '64393334663330303639356134323533393937376561636234363262373662316562616564393838663531393337303563666432633265373130636663666230'
      )
  })

  test('wrong-salt', async () => {
    const setup =
      '{"$schema":"https://mfkdf.com/schema/v2.0.0/policy.json","$id":"8b6874f7-5dbb-4196-bc89-347cd6b02dc6","size":32,"threshold":1,"salt":"nhh2/3AwOf2r2n7uRONoM697IjEKsHfAeyo8NxF1G94=","kdf":{"type":"argon2id","params":{"rounds":2,"memory":24576,"parallelism":1}},"factors":[{"id":"hmacsha1","type":"hmacsha1","pad":"PsS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","salt":"PlS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","params":{"challenge":"5a5f71c3a584b797d3c8f7d0f59653a2234781b06f2540df42946aa380f634a3430e6aad294e392543cc4ecd3da039bfa8041b179d14afd360a104e3354f01dd","pad":"f8d33204be0436f2629d5173e9bd3fc1953cf982"}}]}'

    const derive = await mfkdf.derive.key(JSON.parse(setup), {
      hmacsha1: mfkdf.derive.factors.hmacsha1(
        Buffer.from('0f09b8c89bfefdbc4909432685358eca79912b6a', 'hex')
      )
    })

    const setup2 =
      '{"$schema":"https://mfkdf.com/schema/v2.0.0/policy.json","$id":"8b6874f7-5dbb-4196-bc89-347cd6b02dc6","size":32,"threshold":1,"salt":"nhh2/3AwOf2r2n7uRONoM697IjEKsHfAeyo8NxF1G94=","kdf":{"type":"argon2id","params":{"rounds":2,"memory":24576,"parallelism":1}},"factors":[{"id":"hmacsha1","type":"hmacsha1","pad":"PsS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","salt":"PsS1B6fPovsuMfKZinw6hn0kTw1VEpoM8jRFR/8SyT0=","params":{"challenge":"5a5f71c3a584b797d3c8f7d0f59653a2234781b06f2540df42946aa380f634a3430e6aad294e392543cc4ecd3da039bfa8041b179d14afd360a104e3354f01dd","pad":"f8d33204be0436f2629d5173e9bd3fc1953cf982"}}]}'

    const derive2 = await mfkdf.derive.key(JSON.parse(setup2), {
      hmacsha1: mfkdf.derive.factors.hmacsha1(
        Buffer.from('0f09b8c89bfefdbc4909432685358eca79912b6a', 'hex')
      )
    })

    derive.key
      .toString('hex')
      .should.not.equal(
        '64393334663330303639356134323533393937376561636234363262373662316562616564393838663531393337303563666432633265373130636663666230'
      )

    derive.key.toString('hex').should.not.equal(derive2.key.toString('hex'))
  })

  suite('errors', async () => {
    test('id/type', async () => {
      mfkdf.setup.factors
        .hmacsha1({ id: 12345 })
        .should.be.rejectedWith(TypeError)
    })

    test('id/range', async () => {
      mfkdf.setup.factors
        .hmacsha1({ id: '' })
        .should.be.rejectedWith(RangeError)
    })

    test('secret/type', async () => {
      mfkdf.setup.factors
        .hmacsha1({ secret: 12345 })
        .should.be.rejectedWith(TypeError)
    })

    test('secret/range', async () => {
      mfkdf.setup.factors
        .hmacsha1({ secret: Buffer.from('12345') })
        .should.be.rejectedWith(RangeError)
    })

    test('response/type', async () => {
      (() => {
        mfkdf.derive.factors.hmacsha1(12345)
      }).should.throw(TypeError)
    })
  })
})
