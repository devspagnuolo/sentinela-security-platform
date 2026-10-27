import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Saída enxuta para a imagem Docker (apps/web/.next/standalone); a raiz do monorepo entra no rastreio de dependências.
  output: "standalone",
  outputFileTracingRoot: path.join(process.cwd(), "../.."),
  serverExternalPackages: ["@electric-sql/pglite", "pg"],
  async headers() {
    return [{ source: "/(.*)", headers: [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      { key: "X-Frame-Options", value: "DENY" }
    ] }];
  }
};

export default nextConfig;
