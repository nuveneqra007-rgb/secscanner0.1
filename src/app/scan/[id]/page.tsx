"use client";
import { useEffect, useRef, useState } from "react";
import Image from "next/image";
import { useParams, useRouter } from "next/navigation";
import { ScanResult } from "@/lib/types";
import { loadHistory } from "@/lib/storage";
import { ThreatReport } from "@/components/ThreatReport";

export default function SharedScan() {
  const params = useParams();
  const router = useRouter();
  const id = typeof params.id === "string" ? params.id : "";

  const [result, setResult] = useState<ScanResult | null>(null);
  const [notFound, setNotFound] = useState(false);

  const resolved = useRef(false);

  useEffect(() => {
    if (!id || resolved.current) return;
    resolved.current = true;
    const timer = setTimeout(() => {
      const history = loadHistory();
      const found = history.find((r) => r.id === id) ?? null;
      if (found) {
        setResult(found);
        document.title = `Reporte: ${found.normalizedInput.slice(0, 40)} — SecScanner`;
      } else {
        setNotFound(true);
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [id]);

  const handleNewScan = () => router.push("/");

  if (notFound) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex items-center justify-center px-4">
        <div className="max-w-[420px] w-full text-center space-y-5">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-[#121212] border border-[#333333] flex items-center justify-center text-[#666666]">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold text-white mb-2">Reporte no encontrado</h1>
            <p className="text-sm text-[#A3A3A3] leading-relaxed">
              Este reporte no existe en el almacenamiento local de este navegador. Los reportes se almacenan solo en el dispositivo que realizó el escaneo.
            </p>
          </div>
          <button
            onClick={handleNewScan}
            className="px-6 py-2.5 rounded-xl bg-white text-black font-bold text-sm tracking-wider uppercase hover:bg-[#E0E0E0] transition neon-hover border border-transparent"
          >
            Hacer un nuevo escaneo
          </button>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex items-center justify-center">
        <div className="flex items-center gap-3 text-[#A3A3A3] font-mono text-sm">
          <span className="w-4 h-4 border-2 border-[#333333] border-t-white rounded-full animate-spin" />
          Cargando reporte…
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0A0A0A] animate-fade-in text-white">
      {/* CRT Scanline + Vignette */}
      <div className="crt-scanline" />
      <div className="vignette" />

      {/* Grid Wireframe */}
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:48px_48px]" />

      <header className="sticky top-0 z-40 backdrop-blur-xl bg-[#0A0A0A]/85 border-b border-[#333333]/80">
        <div className="max-w-[1200px] mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <button onClick={handleNewScan} className="flex items-center gap-3 group text-left">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border border-[#333333] group-hover:border-white transition-colors bg-[#121212] p-1">
              <Image
                src="/logo.png"
                alt="SecScanner"
                width={28}
                height={28}
                className="object-contain"
              />
            </div>
            <div className="text-[13px] font-black tracking-[0.2em] text-white">SECSCANNER</div>
          </button>
          <button
            onClick={handleNewScan}
            className="text-xs font-bold px-4 py-2 rounded-lg bg-white text-black hover:bg-[#E0E0E0] transition neon-hover border border-transparent tracking-wider uppercase"
          >
            Nuevo escaneo
          </button>
        </div>
      </header>

      <main className="max-w-[1200px] mx-auto px-4 md:px-6 py-10">
        <div className="mb-5 flex items-center gap-3 px-4 py-3 rounded-xl bg-[#121212] border border-[#333333] text-xs font-mono text-[#A3A3A3]">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="text-white shrink-0">
            <path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/>
            <polyline points="16 6 12 2 8 6"/>
            <line x1="12" y1="2" x2="12" y2="15"/>
          </svg>
          <span>Reporte almacenado localmente en este dispositivo</span>
        </div>
        <ThreatReport result={result} onNewScan={handleNewScan} />
      </main>
    </div>
  );
}
