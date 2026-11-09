import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // output: 'standalone', // Desactivado: Vercel requiere salida estándar para enrutamiento nativo
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
