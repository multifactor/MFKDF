"use client";
import {
  MFKDFIcon as MFKDFIconSVG,
  MFKDFShadow,
} from "@ui/components/resources";
import AnimatedBackground, {
  AnimatedHexBackground,
} from "@ui/components/animated-background";
import CutOut from "@ui/components/icons/cutout";
import Jumbotron from "@ui/components/jumbotron";
import ProductIcon from "@ui/components/logos/product-icon";
import FerrisWheel from "@ui/components/motion/ferris";
import Typography from "@ui/components/typography";
import { Button } from "@ui/components/ui/button";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faArrowRightLong,
  faArrowsRepeat,
  faAsterisk,
  faBellRing,
  faChartSimple,
  faCircleThreeQuartersStroke,
  faCode,
  faDownload,
  faEnvelope,
  faEye,
  faFileLines,
  faFingerprint,
  faFireFlameCurved,
  faKey,
  faLocationDot,
  faLock,
  faMaximize,
  faMessageSms,
  faQrcode,
  faQuestionCircle,
  faRocketLaunch,
  faSimCard,
  faUsbDrive,
} from "@fortawesome/sharp-solid-svg-icons";
import Link from "next/link";
import FlowChart, { FlowChartTextIcon } from "@ui/components/flowchart";
import { JSCode } from "@ui/components/code/js";
import MagicGradient from "@ui/components/ui/gradient";

const snippet1: string = `const derivedKey = await mfkdf.derive.key(JSON.parse(keyPolicy), {
  password: mfkdf.derive.factors.password('Tr0ub4dour'),
  hotp: mfkdf.derive.factors.hotp(365287),
  recovery: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})

console.log(derivedKey.key.toString('hex')) // -> 34d20ced439ec2f871c96ca377f25771
`;

const snippet2: string = `(await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour')
])).entropyBits.real // -> 16.53929514807314

(await mfkdf.setup.key([
  await mfkdf.setup.factors.password('Tr0ub4dour'),
  await mfkdf.setup.factors.hotp(),
  await mfkdf.setup.factors.hmacsha1()
])).entropyBits.real // -> 196.470863717397314`;

const snippet3: string = `const policyBasedKey = await mfkdf.policy.setup(
  await mfkdf.policy.or(
    await mfkdf.setup.factors.uuid({ id: 'recoveryCode' }),
    await mfkdf.policy.and(
      await mfkdf.setup.factors.password('Tr0ub4dour'),
      await mfkdf.setup.factors.totp()
    )
  )
)`;

const snippet4: string = `const key = await mfkdf.derive.key(JSON.parse(keyPolicy), {
  hotp: mfkdf.derive.factors.hotp(365287),
  recoveryCode: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
})

await key.recoverFactor(
  await mfkdf.setup.factors.password('myNewPassword', { id: 'password' })
) // modify key to use new password factor`;

export default function MFKDF2() {
  return (
    <main className="mt-30 max-w-[100vw] overflow-x-hidden">
      <Jumbotron
        variant="primary"
        Background={AnimatedBackground}
        backgroundProps={{
          Element: AnimatedHexBackground,
          effect: "push",
          useRandom: false,
          size: 200,
        }}
      >
        <div className="grid md:grid-cols-12 items-center text-center md:text-left gap-8">
          <div className="md:col-span-7">
            <Typography>
              <h1 className="text-shadow-lg/15 xl:text-5xl!">
                So long, PBKDF2!
              </h1>
              <p className="text-white! opacity-100! text-shadow-lg/15 xl:text-xl!">
                Password-derived keys are only as strong as the passwords
                they&apos;re based on. Securely leverage all of your users&apos;
                authentication factors with MFKDF2.
              </p>
              <div className="flex flex-row flex-wrap gap-2 justify-center md:justify-start xl:hidden">
                <Button variant="primary" asChild className="shadow-md/15">
                  <Link
                    href="/docs/tutorial-01quickstart.html"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faRocketLaunch} /> Get Started
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                >
                  <Link
                    href="https://www.usenix.org/system/files/usenixsecurity23-nair-mfkdf.pdf"
                    target="_blank"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faFileLines} /> Paper
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                >
                  <Link href="/docs" className="no-underline!">
                    <FontAwesomeIcon icon={faCode} /> Docs
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                >
                  <Link
                    href="https://github.com/multifactor/MFKDF/releases"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faDownload} /> Download
                  </Link>
                </Button>
              </div>
              <div className="flex flex-row flex-wrap gap-2 justify-center md:justify-start hidden xl:flex">
                <Button
                  variant="primary"
                  asChild
                  className="shadow-md/15"
                  size="lg"
                >
                  <Link
                    href="/docs/tutorial-01quickstart.html"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faRocketLaunch} /> Get Started
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                  size="lg"
                >
                  <Link
                    href="https://www.usenix.org/system/files/usenixsecurity23-nair-mfkdf.pdf"
                    target="_blank"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faFileLines} /> Paper
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                  size="lg"
                >
                  <Link href="/docs" className="no-underline!">
                    <FontAwesomeIcon icon={faCode} /> Docs
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  asChild
                  className="bg-input! backdrop-blur-xs! shadow-md/15 hover:bg-white/30!"
                  size="lg"
                >
                  <Link
                    href="https://github.com/multifactor/MFKDF/releases"
                    className="no-underline!"
                  >
                    <FontAwesomeIcon icon={faDownload} /> Download
                  </Link>
                </Button>
              </div>
              <div className="flex flex-row gap-2 justify-center md:justify-start mt-6 drop-shadow-md/15">
                <a
                  href="https://github.com/multifactor/MFKDF/releases"
                  className="m-0!"
                >
                  <img
                    src="https://img.shields.io/github/release/multifactor/MFKDF.svg"
                    alt="GitHub release"
                    className="m-0!"
                  />
                </a>
                <a href="/coverage" className="m-0!">
                  <img
                    src="https://img.shields.io/badge/coverage-100%25-brightgreen"
                    alt="Coverage: 100%"
                    className="m-0!"
                  />
                </a>
                <a href="/tests" className="m-0!">
                  <img
                    src="https://img.shields.io/badge/tests-100%25-brightgreen"
                    alt="Tests: 100%"
                    className="m-0!"
                  />
                </a>
              </div>
            </Typography>
          </div>
          <div className="hidden md:block md:col-span-5 text-center xl:hidden">
            <Link href="/">
              <FerrisWheel
                centerIcon={
                  <ProductIcon
                    icon={<MFKDFIconSVG />}
                    secondShadow={<MFKDFShadow />}
                    variant="light"
                    size={110}
                    spacing={33}
                    withTwist={true}
                    hoverSpacing={2.5}
                  />
                }
                orbitingIcons={[
                  <CutOut
                    icon={<FontAwesomeIcon icon={faFingerprint} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="fingerprint"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faLocationDot} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="location"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faEnvelope} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="envelope"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faSimCard} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="simcard"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faUsbDrive} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="usb"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faAsterisk} />}
                    size={44}
                    iconSize={22}
                    color="white"
                    className="drop-shadow-lg"
                    key="asterisk"
                  />,
                ]}
                centerIconSize="4rem"
                orbitingIconSize="1.8rem"
                orbitRadius={120}
                hoverOrbitRadius={160}
                rotationDuration={8}
                transitionDuration={0.3}
                cascadeDelay={0.025}
                centerIconColor="#FFF"
                orbitingIconColor="#FFF"
              />
            </Link>
          </div>
          <div className="md:col-span-5 text-center hidden xl:block">
            <Link href="/">
              <FerrisWheel
                centerIcon={
                  <ProductIcon
                    icon={<MFKDFIconSVG />}
                    secondShadow={<MFKDFShadow />}
                    variant="light"
                    size={130}
                    spacing={39}
                    withTwist={true}
                    hoverSpacing={2.5}
                  />
                }
                orbitingIcons={[
                  <CutOut
                    icon={<FontAwesomeIcon icon={faFingerprint} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="fingerprint"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faLocationDot} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="location"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faEnvelope} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="envelope"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faSimCard} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="simcard"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faUsbDrive} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="usb"
                  />,
                  <CutOut
                    icon={<FontAwesomeIcon icon={faAsterisk} />}
                    size={50}
                    iconSize={25}
                    color="white"
                    className="drop-shadow-lg"
                    key="asterisk"
                  />,
                ]}
                centerIconSize="4rem"
                orbitingIconSize="1.8rem"
                orbitRadius={140}
                hoverOrbitRadius={180}
                rotationDuration={8}
                transitionDuration={0.3}
                cascadeDelay={0.025}
                centerIconColor="#FFF"
                orbitingIconColor="#FFF"
              />
            </Link>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="light">
        <div className="grid grid-cols-4 -my-6">
          <div className="flex flex-col text-center lg:flex-row lg:text-left items-center gap-4">
            <div className="bg-slate-900 rounded-full size-12 flex items-center justify-center">
              <FontAwesomeIcon icon={faLock} className="text-white text-2xl" />
            </div>
            <div className="text">
              <b>Secure</b>
              <p>based on argon2id</p>
            </div>
          </div>
          <div className="flex flex-col text-center lg:flex-row lg:text-left items-center gap-4">
            <div className="bg-slate-900 rounded-full size-12 flex items-center justify-center">
              <FontAwesomeIcon
                icon={faFireFlameCurved}
                className="text-white text-2xl"
              />
            </div>
            <div className="text">
              <b>Fast</b>
              <p>≤ 20ms overhead</p>
            </div>
          </div>
          <div className="flex flex-col text-center lg:flex-row lg:text-left items-center gap-4">
            <div className="bg-slate-900 rounded-full size-12 flex items-center justify-center">
              <FontAwesomeIcon icon={faEye} className="text-white text-2xl" />
            </div>
            <div className="text">
              <b>Transparent</b>
              <p>fully open-source</p>
            </div>
          </div>
          <div className="flex flex-col text-center lg:flex-row lg:text-left items-center gap-4">
            <div className="bg-slate-900 rounded-full size-12 flex items-center justify-center">
              <FontAwesomeIcon
                icon={faMaximize}
                className="text-white text-2xl"
              />
            </div>
            <div className="text">
              <b>Flexible</b>
              <p>modular design</p>
            </div>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="white">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-20 lg:gap-8 lg:items-center my-12 lg:my-6 text-center lg:text-left">
          <div className="lg:col-span-4 xl:col-span-3">
            <div className="origin-center lg:origin-left scale-150 2xl:scale-175">
              <FlowChart
                style="magic"
                className="pt-8 box-content"
                rows={3}
                rowSpacing={40}
                elements={[
                  {
                    type: "bracket",
                    row: 1,
                    col: 1,
                    cols: 2,
                    direction: "horizontal",
                    text: "Knowledge",
                  },
                  {
                    type: "bracket",
                    row: 1,
                    col: 3,
                    cols: 2,
                    direction: "horizontal",
                    text: "Soft Tokens",
                  },
                  {
                    type: "bracket",
                    row: 2,
                    col: 1,
                    cols: 1,
                    direction: "horizontal",
                    text: "USB",
                  },
                  {
                    type: "bracket",
                    row: 2,
                    col: 2,
                    cols: 3,
                    direction: "horizontal",
                    text: "Out-of-Band",
                  },
                  {
                    type: "bracket",
                    row: 3,
                    col: 1,
                    cols: 4,
                    direction: "horizontal",
                    text: "Intrinsic",
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    row: 1,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faQuestionCircle} />,
                    row: 1,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faQrcode} />,
                    row: 1,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: (
                      <FontAwesomeIcon icon={faCircleThreeQuartersStroke} />
                    ),
                    row: 1,
                    col: 4,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faUsbDrive} />,
                    row: 2,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faMessageSms} />,
                    row: 2,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faEnvelope} />,
                    row: 2,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faBellRing} />,
                    row: 2,
                    col: 4,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faFingerprint} />,
                    row: 3,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faLocationDot} />,
                    row: 3,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faChartSimple} />,
                    row: 3,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faSimCard} />,
                    row: 3,
                    col: 4,
                  },
                ]}
              />
            </div>
          </div>
          <div className="lg:col-span-8 xl:col-span-9">
            <Typography>
              <h1>Go beyond passwords</h1>
              <p className="mt-4!">
                Most users have notoriously insecure passwords, with up to 81%
                of them re-using passwords across multiple accounts. MFKDF2
                improves upon password-based key derivation by using all of a
                user&apos;s authentication factors (not just their password) to
                derive a key. MFKDF2 supports deriving key material from a
                variety of common factors, including HOTP, TOTP, and hardware
                tokens like YubiKey.
              </p>
            </Typography>
            <div className="mt-4">
              <JSCode code={snippet1} />
            </div>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="white">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-20 lg:gap-8 lg:items-center my-12 lg:my-6 lg:-mt-12 text-center lg:text-left">
          <div className="lg:col-span-4 xl:col-span-3 lg:order-2 lg:text-right">
            <div className="origin-center lg:origin-right scale-150 2xl:scale-175">
              <FlowChart
                style="magic"
                className="pt-8 box-content"
                cols={4}
                elements={[
                  {
                    type: "line",
                    row: 1,
                    col: 2,
                    cols: 2,
                    muted: true,
                    right: 32,
                    left: 32,
                  },
                  { type: "line", row: 2, col: 2, cols: 2 },
                  { type: "line", row: 2, col: 3, rows: 3 },
                  { type: "line", row: 3, col: 2, cols: 2 },
                  { type: "line", row: 4, col: 2, cols: 2 },
                  {
                    type: "icon",
                    row: 1,
                    col: 2,
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    muted: true,
                  },
                  {
                    type: "icon",
                    row: 1,
                    col: 3,
                    icon: <FontAwesomeIcon icon={faKey} />,
                    muted: true,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    row: 2,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faKey} />,
                    rows: 3,
                    row: 2,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faQrcode} />,
                    row: 3,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faUsbDrive} />,
                    row: 4,
                    col: 2,
                  },
                  {
                    type: "text",
                    text: "14 bits",
                    row: 1,
                    col: 1,
                    muted: true,
                  },
                  {
                    type: "text",
                    text: "14 bits",
                    row: 2,
                    col: 1,
                  },
                  {
                    type: "text",
                    text: "20 bits",
                    row: 3,
                    col: 1,
                  },
                  {
                    type: "text",
                    text: "160 bits",
                    row: 4,
                    col: 1,
                  },
                  {
                    type: "text",
                    text: (
                      <>
                        14 bits
                        <br />
                        &asymp; 16s
                      </>
                    ),
                    row: 1,
                    col: 4,
                    align: "left",
                    muted: true,
                  },
                  {
                    type: "text",
                    text: (
                      <>
                        194 bits
                        <br />
                        &asymp; 10<sup>47</sup> yrs
                      </>
                    ),
                    row: 3,
                    col: 4,
                    align: "left",
                  },
                ]}
              />
            </div>
          </div>
          <div className="lg:col-span-8 xl:col-span-9">
            <Typography>
              <h1>Increased key entropy</h1>
              <p className="mt-4!">
                All factors must be simultaneously correctly guessed to derive a
                key using MFKDF, meaning that they can&apos;t be individually
                brute-force attacked. MFKDF2 keys are thus <i>exponentially</i>{" "}
                harder to crack while remaining just as fast to derive on the
                fly as password-derived keys for users with the correct
                credentials.
              </p>
            </Typography>
            <div className="mt-4">
              <JSCode code={snippet2} />
            </div>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="white">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-20 lg:gap-8 lg:items-center my-12 lg:my-6 lg:-mt-12 text-center lg:text-left">
          <div className="lg:col-span-4 xl:col-span-3">
            <div className="origin-center lg:origin-left scale-150 2xl:scale-175">
              <FlowChart
                style="magic"
                className="pt-8 box-content"
                elements={[
                  { type: "line", row: 1, col: 1, cols: 2 },
                  { type: "line", row: 2, col: 1, cols: 2 },
                  { type: "line", row: 3, col: 1, cols: 2 },
                  { type: "line", row: 4, col: 1, cols: 2 },
                  { type: "line", row: 1, col: 2, rows: 2 },
                  { type: "line", row: 3, col: 2, rows: 2 },
                  { type: "line", row: 3, col: 2, rows: 2 },
                  {
                    type: "line",
                    row: 1,
                    col: 2,
                    rows: 2,
                    cols: 2,
                    direction: "horizontal",
                  },
                  {
                    type: "line",
                    row: 3,
                    col: 2,
                    rows: 2,
                    cols: 2,
                    direction: "horizontal",
                  },
                  {
                    type: "line",
                    row: 1,
                    col: 3,
                    rows: 4,
                    cols: 2,
                    direction: "horizontal",
                  },
                  {
                    type: "line",
                    row: 1,
                    col: 3,
                    rows: 4,
                    cols: 1,
                    top: 40,
                    bottom: 40,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faEnvelope} />,
                    row: 1,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FlowChartTextIcon>AND</FlowChartTextIcon>,
                    rows: 2,
                    row: 1,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FlowChartTextIcon>OR</FlowChartTextIcon>,
                    rows: 4,
                    row: 1,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faKey} />,
                    rows: 4,
                    row: 1,
                    col: 4,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faFingerprint} />,
                    row: 2,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    row: 3,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: <FlowChartTextIcon>AND</FlowChartTextIcon>,
                    rows: 2,
                    row: 3,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faLocationDot} />,
                    row: 4,
                    col: 1,
                  },
                ]}
              />
            </div>
          </div>
          <div className="lg:col-span-8 xl:col-span-9">
            <Typography>
              <h1>Enforce advanced policies</h1>
              <p className="mt-4!">
                MFKDF2 is not all-or-nothing: factor requirements can be
                combined based on simple logical operators like
                &ldquo;AND&rdquo; and &ldquo;OR.&rdquo; In fact, multi-factor
                derived keys can enforce arbitrarily complex authentication
                policies purely cryptographically, without requiring a software
                reference monitor or trusted hardware.
              </p>
            </Typography>
            <div className="mt-4">
              <JSCode code={snippet3} />
            </div>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="white">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-20 lg:gap-8 lg:items-center my-12 lg:my-6 lg:-mt-12 text-center lg:text-left">
          <div className="lg:col-span-4 xl:col-span-3 lg:order-2 lg:text-right">
            <div className="origin-center lg:origin-right scale-150 2xl:scale-175">
              <FlowChart
                style="magic"
                className="pt-8 box-content"
                cols={3}
                elements={[
                  { type: "line", row: 1, col: 2, cols: 2 },
                  { type: "line", row: 2, col: 2, cols: 2 },
                  { type: "line", row: 3, col: 2, cols: 2 },
                  { type: "line", row: 1, col: 3, rows: 3 },
                  { type: "empty", rows: 3, row: 1, col: 1 },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faUsbDrive} />,
                    row: 1,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faKey} />,
                    rows: 3,
                    row: 1,
                    col: 3,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faFingerprint} />,
                    row: 2,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    row: 3,
                    col: 2,
                  },
                  {
                    type: "icon",
                    icon: <FontAwesomeIcon icon={faAsterisk} />,
                    row: 4,
                    col: 1,
                  },
                  {
                    type: "icon",
                    icon: (
                      <FontAwesomeIcon
                        icon={faArrowsRepeat}
                        className="-rotate-45"
                      />
                    ),
                    row: 3,
                    col: 1,
                    rows: 2,
                    cols: 2,
                    variant: "plain",
                  },
                ]}
              />
            </div>
          </div>
          <div className="lg:col-span-8 xl:col-span-9">
            <Typography>
              <h1>Self-service factor recovery</h1>
              <p className="mt-4!">
                Password-derived keys can&apos;t be recovered after a password
                is forgotten without creating a centralized point of failure
                (e.g., a master key). Threshold-based multi-factor derived keys
                can be used to trustlessly recover lost factors on the client
                side without storing any server-side secrets.
              </p>
            </Typography>
            <div className="mt-4">
              <JSCode code={snippet4} />
            </div>
          </div>
        </div>
      </Jumbotron>
      <Jumbotron variant="white" className="-m-12 sm:m-0">
        <div className="sm:rounded-lg overflow-hidden w-full">
          <MagicGradient
            from="#eab308"
            to="#ef4444"
            direction="to-bl"
            className="w-full"
          >
            <div className="text-center text-white p-12 md:p-24">
              <div className="max-w-200 mx-auto">
                <h1 className="text-4xl font-semibold text-balance">
                  Built by the Multifactor research team, for the community
                </h1>
                <p className="text-xl font-light text-balance mt-8">
                  Multifactor is a public benefit company on a mission to
                  redefine zero-trust for the modern web. Learn more about our
                  other research projects, or reach out to explore working
                  together.
                </p>
                <div className="flex flex-row gap-2 justify-center hidden xl:flex mt-8">
                  <Button variant="secondary" asChild size="lg">
                    <Link href="#" className="no-underline!">
                      <FontAwesomeIcon icon={faRocketLaunch} /> Get Started
                    </Link>
                  </Button>
                  <Button variant="link" asChild size="lg">
                    <Link href="#" className="no-underline! text-white!">
                      Learn More
                      <FontAwesomeIcon icon={faArrowRightLong} />
                    </Link>
                  </Button>
                </div>
              </div>
            </div>
          </MagicGradient>
        </div>
      </Jumbotron>
      <Jumbotron variant="light">
        <div className="grid lg:grid-cols-2 text-center lg:text-left gap-8 -my-6">
          <div>
            <b>We appreciate the support of:</b>
            <div className="flex flex-row flex-wrap gap-4 items-center justify-center lg:justify-start mt-4">
              <a href="https://www.zcashcommunity.com/" target="_blank">
                <div className="bg-white rounded-full size-[90px] flex items-center justify-center">
                  <img
                    src="/zcash.svg"
                    height={90}
                    width={90}
                    className="rounded-full"
                    alt="Zcash Foundation Community Grants"
                  />
                </div>
              </a>
              <a href="https://rdi.berkeley.edu/" target="_blank">
                <div className="bg-white rounded-full size-[90px] flex items-center justify-center">
                  <img
                    src="/rdi.jpg"
                    height={70}
                    width={70}
                    className="rounded-full"
                    alt="Berkeley Center for Responsible Decentralized Intelligence"
                  />
                </div>
              </a>
              <a href="https://www.nsf.gov/" target="_blank">
                <div className="bg-white rounded-full size-[90px] flex items-center justify-center">
                  <img
                    src="/nsf.png"
                    height={60}
                    width={60}
                    className="rounded-full"
                    alt="National Science Foundation"
                  />
                </div>
              </a>
              <a href="http://npsc.org/" target="_blank">
                <div className="bg-white rounded-full size-[90px] flex items-center justify-center">
                  <img
                    src="/npsc.png"
                    height={60}
                    width={60}
                    className="rounded-full"
                    alt="National Physical Science Consortium"
                  />
                </div>
              </a>
              <a href="https://www.hertzfoundation.org/" target="_blank">
                <div className="bg-white rounded-full size-[90px] flex items-center justify-center">
                  <img
                    src="/hertz.jpg"
                    height={70}
                    width={70}
                    className="rounded-full"
                    alt="Fannie and John Hertz Foundation"
                  />
                </div>
              </a>
            </div>
          </div>
          <div>
            <b>Evaluated by USENIX:</b>
            <div className="flex flex-row flex-wrap gap-4 items-center justify-center lg:justify-start mt-4">
              <a
                href="https://www.usenix.org/system/files/usenixsecurity23-appendix-nair-mfkdf.pdf"
                target="_blank"
              >
                <img src="usenixbadges-available.png" height={90} width={90} />
              </a>
              <a
                href="https://www.usenix.org/system/files/usenixsecurity23-appendix-nair-mfkdf.pdf"
                target="_blank"
              >
                <img src="usenixbadges-functional.png" height={90} width={90} />
              </a>
              <a
                href="https://www.usenix.org/system/files/usenixsecurity23-appendix-nair-mfkdf.pdf"
                target="_blank"
              >
                <img src="usenixbadges-reproduced.png" height={90} width={90} />
              </a>
              <a
                href="https://www.usenix.org/system/files/usenixsecurity23-appendix-nair-mfkdf.pdf"
                target="_blank"
              >
                <img
                  src="usenixbadges-distinguished.png"
                  height={90}
                  width={90}
                />
              </a>
            </div>
          </div>
        </div>
      </Jumbotron>
    </main>
  );
}
