"use client";

import React, { useState } from "react";

import { Accordion } from "@ui/components/ui/accordion";
import { Button } from "@ui/components/ui/button";
import {
  NavigationMenu,
  NavigationMenuList,
} from "@ui/components/ui/navigation-menu";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@ui/components/ui/sheet";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faBars,
  faRocketLaunch,
  faUserPlus,
} from "@fortawesome/sharp-solid-svg-icons";
import Link from "next/link";
import AnimatedBackground, {
  AnimatedChecksBackground,
} from "@ui/components/animated-background";
import Check from "@ui/components/logos/multifactor/check";
import ProductIcon from "@ui/components/logos/product-icon";
import clsx from "clsx";
import { MFKDFLogoSm } from "@ui/components/logos/mfkdf";
import { renderMenuItem, renderMobileMenuItem } from "@ui/components/ui/navbar";

const menu = [
  {
    title: "Docs",
    url: "/docs",
  },
  {
    title: "Tutorials",
    items: [
      {
        title: "Getting Started",
        url: "/docs/tutorial-01quickstart",
      },
      {
        title: "Basic Key Derivation",
        url: "/docs/tutorial-02mfkdf",
      },
      {
        title: "Threshold Key Derivation",
        url: "/docs/tutorial-03threshold",
      },
      {
        title: "Key Stacking",
        url: "/docs/tutorial-04stacking",
      },
      {
        title: "Policy Enforcement",
        url: "/docs/tutorial-05policy",
      },
      {
        title: "Entropy Estimation",
        url: "/docs/tutorial-06entropy",
      },
      {
        title: "Recovery and Reconstitution",
        url: "/docs/tutorial-07reconstitution",
      },
      {
        title: "Factor Persistence",
        url: "/docs/tutorial-08persistence",
      },
    ],
  },
  {
    title: "Testing",
    url: "/tests",
  },
  {
    title: "Coverage",
    url: "/coverage",
  },
  {
    title: "Demos",
    items: [
      {
        title: "Centralized Demo",
        url: "https://demo.mfkdf.com",
      },
      {
        title: "Decentralized Demo",
        url: "https://wallet.mfkdf.com",
      },
    ],
  },
  {
    title: "Videos",
    url: "https://multifactor.com/videos/tags/mfkdf",
  },
  {
    title: "Blog",
    url: "https://multifactor.com/blog/tags/mfkdf",
  },
];

export function SpecialNavCard({
  link,
  children,
  background = AnimatedChecksBackground,
  icon = <Check />,
  shadow,
}: {
  link: string;
  children?: React.ReactNode;
  background?: React.ComponentType<{
    size: number;
    mousePosition: { x: number; y: number } | null;
  }>;
  icon?: React.ReactElement<{ style?: React.CSSProperties }>;
  shadow?: React.ReactElement<{ style?: React.CSSProperties }>;
}) {
  const [isHovering, setIsHovering] = useState(false);

  const handleMouseEnter = () => {
    setIsHovering(true);
  };

  const handleMouseLeave = () => {
    setIsHovering(false);
  };

  return (
    <Link
      className="h-full w-full rounded-md bg-linear-to-b no-underline outline-hidden select-none rounded-md overflow-hidden p-0! m-0 inset-0 relative block"
      href={link}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <div className="bg-gradient-to-tr from-mf-primary-dark to-mf-primary-light text-white dark relative h-full w-full p-0 m-0 inset-0 absolute [&>*]:absolute [&>*]:inset-0">
        <AnimatedBackground
          Element={background}
          size={75}
          effect="push"
          useRandom={false}
        >
          <div
            className={clsx(
              "p-6 flex relative w-full h-full inset-0 flex-col justify-end bg-gradient-to-t to-transparent transition-colors",
              isHovering ? "from-black/5" : "from-black/15"
            )}
          >
            <div>
              <ProductIcon
                icon={icon}
                variant="light"
                size={40}
                spacing={12}
                isHovering={isHovering}
                secondShadow={shadow}
              />
            </div>
            {children}
          </div>
        </AnimatedBackground>
      </div>
    </Link>
  );
}

export default function MFKDFNavbar() {
  return (
    <nav className="px-12 border-b border-slate-300 fixed top-12 w-full bg-slate-50 z-99 isolate h-18">
      <div className="container mx-auto h-full flex items-center">
        {/* Desktop Menu */}
        <nav className="hidden justify-between lg:flex flex-1 h-full items-center justify-between">
          <div className="flex items-center gap-6">
            {/* Logo */}
            <div className="text-[0px] text-slate-900 w-50">
              <Link href="/">
                <MFKDFLogoSm variant="primary" />
              </Link>
            </div>
            <div className="flex items-center">
              <NavigationMenu>
                <NavigationMenuList>
                  {menu.map((item) => renderMenuItem(item as MenuItem))}
                </NavigationMenuList>
              </NavigationMenu>
            </div>
          </div>
          <div className="flex gap-2">
            <Button asChild variant="primary" className="w-[184px]">
              <Link href="/docs/tutorial-01quickstart">
                <FontAwesomeIcon icon={faRocketLaunch} />
                Use MFKDF
              </Link>
            </Button>
          </div>
        </nav>

        {/* Mobile Menu */}
        <div className="block w-full lg:hidden">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="text-[0px] text-slate-900">
              <Link href="/">
                <MFKDFLogoSm variant="primary" />
              </Link>
            </div>
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon">
                  <FontAwesomeIcon icon={faBars} />
                </Button>
              </SheetTrigger>
              <SheetContent className="overflow-y-auto">
                <SheetHeader>
                  <SheetTitle>
                    {/* Logo */}
                    <div className="text-[0px] text-slate-900">
                      <Link href="/">
                        <MFKDFLogoSm variant="primary" />
                      </Link>
                    </div>
                  </SheetTitle>
                </SheetHeader>
                <div className="flex flex-col gap-6 p-4">
                  <Accordion
                    type="single"
                    collapsible
                    className="flex w-full flex-col gap-4"
                  >
                    {menu.map((item) => renderMobileMenuItem(item as MenuItem))}
                  </Accordion>

                  <div className="flex flex-col gap-3">
                    <Button asChild variant="primary">
                      <Link href="/docs/tutorial-01quickstart">
                        <FontAwesomeIcon icon={faUserPlus} />
                        Use MFKDF
                      </Link>
                    </Button>
                  </div>
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </nav>
  );
}

interface MenuItem {
  title: string;
  url: string;
  description?: string;
  icon?: React.ReactNode;
  mfIcon?: React.ReactElement<{ style?: React.CSSProperties }>;
  mfShadow?: React.ReactElement<{ style?: React.CSSProperties }>;
  items?: MenuItem[];
}
