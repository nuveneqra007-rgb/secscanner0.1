import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecScanner — Análisis de Amenazas",
  description:
    "Herramienta de Threat Intelligence para análisis de URLs, IPs, hashes y APKs. Heurística avanzada, reputación y reporte técnico en segundos.",
  keywords: ["ciberseguridad", "threat intelligence", "phishing", "malware", "OSINT", "análisis de amenazas"],
  openGraph: {
    title: "SecScanner — Análisis de Amenazas",
    description:
      "Detecta amenazas en URLs, IPs, hashes y APKs. Reporte técnico con score de riesgo, hallazgos por severidad y recomendaciones SOC.",
    type: "website",
    locale: "es_ES",
    siteName: "SecScanner",
  },
  twitter: {
    card: "summary",
    title: "SecScanner — Análisis de Amenazas",
    description:
      "Detecta amenazas en URLs, IPs, hashes y APKs. Reporte técnico con score de riesgo, hallazgos por severidad y recomendaciones SOC.",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className="h-full antialiased dark">
      <body
        className="min-h-full flex flex-col bg-[#0A0A0A] text-zinc-100 selection:bg-white/20 selection:text-white"
        style={{
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial",
        }}
      >
        {children}
      </body>
    </html>
  );
}
