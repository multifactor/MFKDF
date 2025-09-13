import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  transpilePackages: ["@multifactor-frontend/multifactor-ui"],
  output: "export",
};

export default nextConfig;
