/* eslint no-unused-expressions: "off" */
const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
chai.should();

const mfkdf = require("../../src");
const { suite, test } = require("mocha");

suite("tutorials", () => {
  test("Persistence", async () => {
    // setup 3-factor multi-factor derived key
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("password1", { id: "password1" }),
      await mfkdf.setup.factors.password("password2", { id: "password2" }),
      await mfkdf.setup.factors.password("password3", { id: "password3" }),
    ]);
    setup.key.toString("hex"); // -> 6458…dc3c

    // persist one of the factors
    const factor2 = setup.persistFactor("password2");

    // derive key with 2 factors
    const derived = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password("password1"),
      password2: mfkdf.derive.factors.persisted(factor2),
      password3: mfkdf.derive.factors.password("password3"),
    });
    derived.key.toString("hex"); // -> 6458…dc3c

    setup.key.toString("hex").should.equal(derived.key.toString("hex"));
  });

  test("Reconstitution", async () => {
    // setup 16 byte 3-factor multi-factor derived key with a password, HOTP code, and UUID code
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("password"),
      await mfkdf.setup.factors.hotp({
        secret: Buffer.from("abcdefghijklmnopqrst"),
      }),
      await mfkdf.setup.factors.uuid({
        uuid: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      }),
    ]);
    setup.key.toString("hex"); // -> 34d2…5771

    // reconstitute key to change password
    await setup.recoverFactor(
      await mfkdf.setup.factors.password("newPassword")
    );

    // derive key using the 3 factors (including the new password)
    const derive = await mfkdf.derive.key(setup.policy, {
      password: mfkdf.derive.factors.password("newPassword"),
      hotp: mfkdf.derive.factors.hotp(241063),
      uuid: mfkdf.derive.factors.uuid("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
    });
    derive.key.toString("hex"); // -> 34d2…5771
  });

  test("Stacking", async () => {
    // setup key with stack factor
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.stack([
          await mfkdf.setup.factors.password("password1", { id: "password1" }),
          await mfkdf.setup.factors.password("password2", { id: "password2" }),
        ]),
        await mfkdf.setup.factors.password("password3", { id: "password3" }),
      ],
      { threshold: 1 }
    );
    setup.key.toString("hex"); // -> 01d0…2516

    // derive key with stack factor
    const derive = await mfkdf.derive.key(setup.policy, {
      stack: mfkdf.derive.factors.stack({
        password1: mfkdf.derive.factors.password("password1"),
        password2: mfkdf.derive.factors.password("password2"),
      }),
    });
    derive.key.toString("hex"); // -> 01d0…2516

    setup.key.toString("hex").should.equal(derive.key.toString("hex"));
  });

  test("Policy", async () => {
    // Setup policy-based multi-factor derived key
    const policy = await mfkdf.policy.setup(
      await mfkdf.policy.and(
        await mfkdf.policy.or(
          await mfkdf.setup.factors.password("password1", { id: "password1" }),
          await mfkdf.setup.factors.password("password2", { id: "password2" })
        ),
        await mfkdf.policy.or(
          await mfkdf.setup.factors.password("password3", { id: "password3" }),
          await mfkdf.setup.factors.password("password4", { id: "password4" })
        )
      )
    );
    policy.key.toString("hex"); // -> 34d2…5771

    // Check which factors can derive key
    mfkdf.policy.evaluate(policy.policy, ["password1", "password3"]); // -> true
    mfkdf.policy.evaluate(policy.policy, ["password3", "password4"]); // -> false

    // Derive policy-based multi-factor derived key
    const derived = await mfkdf.policy.derive(policy.policy, {
      password1: mfkdf.derive.factors.password("password1"),
      password4: mfkdf.derive.factors.password("password4"),
    });
    derived.key.toString("hex"); // -> 34d2…5771

    mfkdf.policy.evaluate(policy.policy, ["password1", "password3"]).should.be
      .true;
    mfkdf.policy.evaluate(policy.policy, ["password3", "password4"]).should.be
      .false;
    policy.key.toString("hex").should.equal(derived.key.toString("hex"));
  });

  test("Threshold", async () => {
    // setup 16 byte 2-of-3 multi-factor derived key with a password, HOTP code, and UUID code
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password("password"),
        await mfkdf.setup.factors.hotp({
          secret: Buffer.from("abcdefghijklmnopqrst"),
        }),
        await mfkdf.setup.factors.uuid({
          uuid: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        }),
      ],
      { threshold: 2 }
    );
    setup.key.toString("hex"); // -> 34d2…5771

    const derive = await mfkdf.derive.key(setup.policy, {
      hotp: mfkdf.derive.factors.hotp(241063),
      uuid: mfkdf.derive.factors.uuid("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
    });
    derive.key.toString("hex"); // -> 34d2…5771

    setup.key.toString("hex").should.include(derive.key.toString("hex"));
  });

  test("Entropy", async () => {
    // password-only 256-bit key
    const key1 = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("Tr0ub4dour"),
    ]);
    key1.entropyBits.real; // -> 16.53929514807314

    // password-and-hotp 256-bit key
    const key2 = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("Tr0ub4dour"),
      await mfkdf.setup.factors.hotp(),
    ]);
    key2.entropyBits.real; // -> 36.470863717397314

    Math.floor(key1.entropyBits.real).should.equal(16);
    Math.floor(key2.entropyBits.real).should.equal(36);

    const weak = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("abcdefgh"),
    ]);

    // High theoretical entropy due to long password
    weak.entropyBits.theoretical; // -> 64

    // Low real entropy due to weak password
    weak.entropyBits.real; // -> 5.044394119358453

    Math.floor(weak.entropyBits.theoretical).should.equal(64);
    Math.floor(weak.entropyBits.real).should.equal(5);

    const all = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("Tr0ub4dour", { id: "password1" }),
      await mfkdf.setup.factors.uuid(),
      await mfkdf.setup.factors.password("abcdefgh", { id: "password2" }),
    ]);

    const threshold = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password("Tr0ub4dour", { id: "password1" }),
        await mfkdf.setup.factors.uuid(),
        await mfkdf.setup.factors.password("abcdefgh", { id: "password2" }),
      ],
      { threshold: 2 }
    );

    all.entropyBits.real; // -> 143.5836892674316
    threshold.entropyBits.real; // -> 21.583689267431595

    Math.floor(all.entropyBits.real).should.equal(143);
    Math.floor(threshold.entropyBits.real).should.equal(21);

    const policy = await mfkdf.policy.setup(
      await mfkdf.policy.and(
        await mfkdf.setup.factors.password("password1", { id: "password1" }),
        await mfkdf.policy.and(
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password("password2", {
              id: "password2",
            }),
            await mfkdf.setup.factors.password("password3", { id: "password3" })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password("password4", {
              id: "password4",
            }),
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password("password5", {
                id: "password5",
              }),
              await mfkdf.setup.factors.password("password6", {
                id: "password6",
              })
            )
          )
        )
      )
    );

    policy.entropyBits.real; // -> 45.27245744876085
    Math.floor(policy.entropyBits.real).should.equal(45);
  });

  test("Multi-Factor Key Derivation", async () => {
    // setup 16 byte 3-factor multi-factor derived key with a password, HOTP code, and UUID code
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password("password"),
      await mfkdf.setup.factors.hotp({
        secret: Buffer.from("abcdefghijklmnopqrst"),
      }),
      await mfkdf.setup.factors.uuid({
        uuid: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      }),
    ]);

    setup.key.toString("hex"); // -> 34d2…5771

    // save key policy
    const policy = JSON.stringify(setup.policy);

    // derive key using the 3 factors
    const derive = await mfkdf.derive.key(JSON.parse(policy), {
      password: mfkdf.derive.factors.password("password"),
      hotp: mfkdf.derive.factors.hotp(241063),
      uuid: mfkdf.derive.factors.uuid("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
    });

    derive.key.toString("hex"); // -> 34d2…5771

    // save new key policy
    const newPolicy = JSON.stringify(derive.policy);

    setup.key.toString("hex").should.equal(derive.key.toString("hex"));
    newPolicy.should.be.a("string");
  });
});
