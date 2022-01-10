[![MFKDF](https://raw.githubusercontent.com/multifactor/MFKDF/master/site/logo.png "MFKDF")](https://mfkdf.com/ "MFKDF")

# Roadmap
### Features
- ~~standard KDFs~~ _added in v0.1.0_
- ~~k-of-n MFKDF~~ _added in v0.1.0_
- symmetric & asymmetric key constructions
- 1-factor MFKDF (n=1)
- 1-of-n MFKDF (m=1)
- non secret-shared MFKDF (m=n)
- MFKDF authentication
- variable polynomial bitsize (n>255)
- add/remove/recover factors

### Factors
- ~~passwords~~ _added in v0.2.0_
- ~~security questions~~ _added in v0.3.0_
- ~~recovery codes~~ _added in v0.4.0_
- browser memory / device identifiers (UUID)
- totp/hotp
- fido u2f
- sso (oauth/oidc)
- 3rd-party out-of-band (sms/email/push)
- trusted hardware
- mpc
- biometric
- location
- behavioral
