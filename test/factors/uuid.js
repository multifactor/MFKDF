/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('factors/uuid', () => {
  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' }),
      await mfkdf.setup.factors.uuid({ id: 'uuid2', uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' }),
      await mfkdf.setup.factors.uuid({ id: 'uuid3', uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' })
    ], { threshold: 2 })

    setup.outputs.should.deep.equal({
      uuid1: { uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' },
      uuid2: { uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' },
      uuid3: { uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' }
    })

    const derive1 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
    })

    const derive2 = await mfkdf.derive.key(setup.policy, {
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    const derive3 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    const derive4 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'),
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive2.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive3.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive4.key.toString('hex'))

    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive1.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive2.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive3.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive4.policy))
  })

  test('invalid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' }),
      await mfkdf.setup.factors.uuid({ id: 'uuid2', uuid: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' }),
      await mfkdf.setup.factors.uuid({ id: 'uuid3', uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' })
    ], { threshold: 2 })

    const derive1 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6e'),
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
    })

    const derive2 = await mfkdf.derive.key(setup.policy, {
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0c')
    })

    const derive3 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6b'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0d')
    })

    const derive4 = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-ab8dfbbd4bed'),
      uuid2: mfkdf.derive.factors.uuid('1b9d6bcd-bbfd-4b2d-9b5d-2b0d7b3dcb6d'),
      uuid3: mfkdf.derive.factors.uuid('6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b')
    })

    setup.key.toString('hex').should.not.equal(derive1.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive2.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive3.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive4.key.toString('hex'))
  })
})
