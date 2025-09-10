/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('factors/stack', () => {
  test('errors/id/type', async () => {
    mfkdf.setup.factors
      .stack(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ],
        { id: 12345 }
      )
      .should.be.rejectedWith(TypeError)
  })

  test('errors/id/range', async () => {
    mfkdf.setup.factors
      .stack(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' })
        ],
        { id: '' }
      )
      .should.be.rejectedWith(RangeError)
  })

  test('valid', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.stack(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            }),
            await mfkdf.setup.factors.password('password2', {
              id: 'password2'
            })
          ],
          { id: 'stack1' }
        ),
        await mfkdf.setup.factors.stack(
          [
            await mfkdf.setup.factors.password('password3', {
              id: 'password3'
            }),
            await mfkdf.setup.factors.password('password4', {
              id: 'password4'
            })
          ],
          { id: 'stack2' }
        )
      ],
      { threshold: 1 }
    )

    setup.policy.factors[0].params.should.not.have.property('hmac')

    const derive1 = await mfkdf.derive.key(setup.policy, {
      stack1: mfkdf.derive.factors.stack({
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
    })

    const derive2 = await mfkdf.derive.key(setup.policy, {
      stack2: mfkdf.derive.factors.stack({
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      })
    })

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
  })
})
