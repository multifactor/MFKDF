const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')

suite('stage', () => {
  test('basic', async () => {
    const passwordSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.password('password'))

    const setup = await mfkdf.setup.key([
      passwordSetup
    ], { kdf: 'hkdf' })

    const passwordDerive = await mfkdf.stage.factor.derive(mfkdf.derive.factors.password('password'), setup.policy.factors[0].params)

    const derive = await mfkdf.derive.key(setup.policy, {
      password: passwordDerive
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('full', async () => {
    const keyPair = await crypto.webcrypto.subtle.generateKey(
      { hash: 'SHA-256', modulusLength: 2048, name: 'RSA-OAEP', publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ['encrypt', 'decrypt']
    )

    const passwordSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.password('password'))
    const hmacsha1Setup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.hmacsha1())
    const hotpSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.hotp({ secret: Buffer.from('hello world') }))
    const oobaSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.ooba({ key: keyPair.publicKey, params: {} }))
    const questionSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.question('fido'))
    const totpSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.totp({ secret: Buffer.from('hello world'), time: 1650430806597 }))
    const uuidSetup = await mfkdf.stage.factor.setup(mfkdf.setup.factors.uuid({ uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' }))

    const setup = await mfkdf.setup.key([
      passwordSetup, hmacsha1Setup, hotpSetup, oobaSetup, questionSetup, totpSetup, uuidSetup
    ], { kdf: 'hkdf' })

    const secret = setup.outputs.hmacsha1.secret
    const challenge = Buffer.from(setup.policy.factors[1].params.challenge, 'hex')
    const response = crypto.createHmac('sha1', secret).update(challenge).digest()
    const next = setup.policy.factors[3].params.next
    const decrypted = await crypto.webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, keyPair.privateKey, Buffer.from(next, 'hex'))
    const json = JSON.parse(Buffer.from(decrypted).toString())
    const code = json.code

    const password = await mfkdf.stage.factor.derive(mfkdf.derive.factors.password('password'), setup.policy.factors[0].params, setup.key)
    const hmacsha1 = await mfkdf.stage.factor.derive(mfkdf.derive.factors.hmacsha1(response), setup.policy.factors[1].params, setup.key)
    const hotp = await mfkdf.stage.factor.derive(mfkdf.derive.factors.hotp(365287), setup.policy.factors[2].params, setup.key)
    const ooba = await mfkdf.stage.factor.derive(mfkdf.derive.factors.ooba(code), setup.policy.factors[3].params, setup.key)
    const question = await mfkdf.stage.factor.derive(mfkdf.derive.factors.question('fido'), setup.policy.factors[4].params, setup.key)
    const totp = await mfkdf.stage.factor.derive(mfkdf.derive.factors.totp(528258, { time: 1650430943604 }), setup.policy.factors[5].params, setup.key)
    const uuid = await mfkdf.stage.factor.derive(mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'), setup.policy.factors[6].params, setup.key)

    const derive = await mfkdf.derive.key(setup.policy, {
      password, hmacsha1, hotp, ooba, question, totp, uuid
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })
})
