/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('mfkdf2/hints', () => {
  test('getHint', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      })
    ])

    const hint = setup.getHint('password1', 7)

    hint.should.be.a('string')
    hint.length.should.equal(7)

    const hinta = setup.getHint('password1', 24)
    hinta.should.be.a('string')
    hinta.length.should.equal(24)

    const derived = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })
    derived.key.toString('hex').should.equal(setup.key.toString('hex'))

    const hint2 = derived.getHint('password1', 7)
    hint2.should.equal(hint)

    const hinta2 = derived.getHint('password1', 24)
    hinta2.should.equal(hinta)

    const derived2 = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('wrongpassword')
      },
      false
    )

    const hinta3 = derived2.getHint('password1', 24)
    hinta3.should.not.equal(hinta)
  })

  test('addHint', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ],
      {
        integrity: false
      }
    )

    setup.addHint('password1')

    setup.policy.factors[0].hint.should.be.a('string')
    setup.policy.factors[0].hint.length.should.equal(7)

    setup.addHint('password1', 24)

    setup.policy.factors[0].hint.should.be.a('string')
    setup.policy.factors[0].hint.length.should.equal(24)

    await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1')
      },
      false
    )

    await mfkdf.derive
      .key(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password2')
        },
        false
      )
      .should.be.rejectedWith(RangeError)
  })

  test('coverage', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ],
      {
        integrity: false
      }
    );
    (() => setup.getHint()).should.throw(TypeError);
    (() => setup.getHint(123)).should.throw(TypeError);
    (() => setup.getHint('unknown')).should.throw(RangeError);
    (() => setup.getHint('password1', 'string')).should.throw(TypeError);
    (() => setup.getHint('password1', 0)).should.throw(TypeError);
    (() => setup.getHint('password1', 300)).should.throw(TypeError)
  })
})
