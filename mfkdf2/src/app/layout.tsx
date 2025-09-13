import "./globals.css";

import "@ui/library/index";

import Body from "@ui/components/page";

import MultifactorNavbar from "@ui/components/nav/navbar/multifactor";
import MultifactorFooter from "@ui/components/nav/footer/multifactor";
import MFKDFNavbar from "../components/navbar";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: {
    template: "%s | MFKDF2",
    default: "Multi-Factor Key Derivation Function (MFKDF2) by Multifactor",
  },
  applicationName: "MFKDF2",
  keywords: [
    "Cryptography",
    "MFKDF2",
    "Multifactor",
    "Key Derivation",
    "Security",
  ],
  authors: [{ name: "Vivek Nair", url: "https://nair.me" }],
  creator: "Vivek Nair",
  publisher: "Multifactor",
  description:
    "The Next-Generation Multi-Factor Key Derivation Function (MFKDF2) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a password-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors, including HOTP, TOTP, and hardware tokens like YubiKey. MFKDF also enables self-service account recovery via K-of-N (secret-sharing style) key derivation, eliminating the need for central recovery keys, and supports arbitrarily complex key derivation policies.",
  openGraph: {
    title: "Multi-Factor Key Derivation Function (MFKDF2) by Multifactor",
    description:
      "The Next-Generation Multi-Factor Key Derivation Function (MFKDF2) is a function that takes multiple inputs and outputs a string of bytes that can be used as a cryptographic key. It serves the same purpose as a password-based key derivation function (PBKDF), but is stronger than password-based key derivation due to its support for multiple authentication factors, including HOTP, TOTP, and hardware tokens like YubiKey. MFKDF also enables self-service account recovery via K-of-N (secret-sharing style) key derivation, eliminating the need for central recovery keys, and supports arbitrarily complex key derivation policies.",
    url: "https://mfkdf.com",
    siteName: "MFKDF2",
    locale: "en_US",
    type: "website",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <Body>
        <MultifactorNavbar primary={false} />
        <MFKDFNavbar />
        {children}
        <MultifactorFooter />
      </Body>
    </html>
  );
}
