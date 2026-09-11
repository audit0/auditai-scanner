import type { NextConfig } from "next";

const nextConfig: NextConfig = { transpilePackages: ["@kit/supabase", "@kit/invoices"] };

export default nextConfig;
