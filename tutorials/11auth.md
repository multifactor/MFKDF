## Introduction
A major advantage of using multi-factor derived keys is the ability for user data to remain protected by all of their authentication factors even if central authentication servers are compromised by an attacker, as keys are derived entirely on the client side. This purpose is defeated if authentication factors (eg. an HOTP key) must be stored on the server for verification. Therefore, it is suggested that the multi-factor derived key itself be used for user authentication. Because the multi-factor derived key cannot be obtained without presenting a valid combination of factors according to the key policy, using the key to authenticate serves as proof that a valid set of factors has been presented by the user.

## Authentication Protocols
This library supports a number of standardized key-based authentication protocols which can be used to securely authenticate a user based on their multi-factor derived key. The protocols included are summarized below:

| Name | Cryptography | Freshness | Prove | Verify | Key |
| ---- | ------------ | --------- | ----- | ------ | --- |
| ISO 9798 2-Pass Unilateral Auth | Symmetric | Challenge | [ISO97982PassUnilateralAuthSymmetric]{@link MFKDFDerivedKey.ISO97982PassUnilateralAuthSymmetric} | [VerifyISO97982PassUnilateralAuthSymmetric]{@link auth.VerifyISO97982PassUnilateralAuthSymmetric} | [ISO9798SymmetricKey]{@link MFKDFDerivedKey.ISO9798SymmetricKey}
| ISO 9798 Public-Key 2-Pass Unilateral Auth | Asymmetric | Challenge | [ISO97982PassUnilateralAuthAsymmetric]{@link MFKDFDerivedKey.ISO97982PassUnilateralAuthAsymmetric} | [VerifyISO97982PassUnilateralAuthAsymmetric]{@link auth.VerifyISO97982PassUnilateralAuthAsymmetric} | [ISO9798AsymmetricKey]{@link MFKDFDerivedKey.ISO9798AsymmetricKey}
| ISO 9798 2-Pass Unilateral Auth over CCF | Hash | Challenge | [ISO97982PassUnilateralAuthCCF]{@link MFKDFDerivedKey.ISO97982PassUnilateralAuthCCF} | [VerifyISO97982PassUnilateralAuthCCF]{@link auth.VerifyISO97982PassUnilateralAuthCCF} | [ISO9798CCFKey]{@link MFKDFDerivedKey.ISO9798CCFKey}
| ISO 9798 1-Pass Unilateral Auth | Symmetric | Timestamp | [ISO97981PassUnilateralAuthSymmetric]{@link MFKDFDerivedKey.ISO97981PassUnilateralAuthSymmetric} | [VerifyISO97981PassUnilateralAuthSymmetric]{@link auth.VerifyISO97981PassUnilateralAuthSymmetric} | [ISO9798SymmetricKey]{@link MFKDFDerivedKey.ISO9798SymmetricKey}
| ISO 9798 Public-Key 1-Pass Unilateral Auth | Asymmetric | Timestamp | [ISO97981PassUnilateralAuthAsymmetric]{@link auth.ISO97981PassUnilateralAuthAsymmetric} | [VerifyISO97981PassUnilateralAuthAsymmetric]{@link auth.VerifyISO97981PassUnilateralAuthAsymmetric} | [ISO9798AsymmetricKey]{@link MFKDFDerivedKey.ISO9798AsymmetricKey}
| ISO 9798 1-Pass Unilateral Auth over CCF | Hash | Timestamp | [ISO97981PassUnilateralAuthCCF]{@link MFKDFDerivedKey.ISO97981PassUnilateralAuthCCF} | [VerifyISO97981PassUnilateralAuthCCF]{@link auth.VerifyISO97981PassUnilateralAuthCCF} | [ISO9798CCFKey]{@link MFKDFDerivedKey.ISO9798CCFKey}

## Authentication Example
The following example uses ISO 9798 2-Pass Unilateral Auth:

```
// setup multi-factor derived key
const key = await mfkdf.setup.key([await mfkdf.setup.factors.password('password')])

// challenger: create random challenge
const challenge = crypto.randomBytes(32)
const identity = Buffer.from('Challenger')

// responder: generate response
const response = await key.ISO97982PassUnilateralAuthSymmetric(challenge, identity)

// verifier: verify response
const authKey = await key.ISO9798SymmetricKey()
const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, response, authKey) // -> true
```

Each of the supported authentication protocols has its own dedicated example, so please check the documentation for each protocol if you feel another protocol is a better fit for your project.
