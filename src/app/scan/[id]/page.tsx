"use client";
import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ScanResult } from "@/lib/types";
import { loadHistory } from "@/lib/storage";
import { ThreatReport } from "@/components/ThreatReport";

export default function SharedScan() {
  const params  = useParams();
  const router  = useRouter();
  const id      = typeof params.id === "string" ? params.id : "";

  const [result,   setResult]   = useState<ScanResult | null>(null);
  const [notFound, setNotFound] = useState(false);

  const resolved = useRef(false);

  useEffect(() => {
    if (!id || resolved.current) return;
    resolved.current = true;
    const timer = setTimeout(() => {
      const history = loadHistory();
      const found   = history.find((r) => r.id === id) ?? null;
      if (found) {
        setResult(found);
        // Fix #7: actualizar título dinámicamente
        document.title = `Reporte: ${found.normalizedInput.slice(0, 40)} — ThreatScan`;
      } else {
        setNotFound(true);
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [id]);

  const handleNewScan = () => router.push("/");

  if (notFound) {
    return (
      <div className="min-h-screen bg-[#09090b] flex items-center justify-center px-4">
        <div className="max-w-[420px] w-full text-center space-y-5">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-500">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold text-white mb-2">Reporte no encontrado</h1>
            <p className="text-sm text-zinc-400 leading-relaxed">
              Este reporte no existe en el historial de este navegador. Los reportes se almacenan solo en el dispositivo que realizó el escaneo.
            </p>
          </div>
          <button
            onClick={handleNewScan}
            className="px-6 py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-sm hover:bg-cyan-400 transition"
          >
            Hacer un nuevo escaneo
          </button>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="min-h-screen bg-[#09090b] flex items-center justify-center">
        <div className="flex items-center gap-3 text-zinc-500 font-mono text-sm">
          <span className="w-4 h-4 border-2 border-zinc-700 border-t-cyan-500 rounded-full animate-spin" />
          Cargando reporte…
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#09090b] animate-fade-in">
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,#27272a_1px,transparent_1px),linear-gradient(to_bottom,#27272a_1px,transparent_1px)] bg-[size:32px_32px] opacity-[0.05]" />
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(ellipse_80%_40%_at_50%_-10%,rgba(6,182,212,0.08),transparent)]" />

      <header className="sticky top-0 z-40 backdrop-blur-xl bg-zinc-950/80 border-b border-zinc-800/60">
        <div className="max-w-[1200px] mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <button onClick={handleNewScan} className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg bg-cyan-500 flex items-center justify-center shrink-0 group-hover:bg-cyan-400 transition">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#09090b" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
              </svg>
            </div>
            <div className="leading-none">
              <div className="text-[13px] font-black tracking-[0.15em] text-white">THREATSCAN</div>
              <div className="text-[10px] font-mono tracking-widest text-zinc-500 mt-0.5">THREAT INTELLIGENCE</div>
            </div>
          </button>
          <button
            onClick={handleNewScan}
            className="text-xs font-bold px-4 py-2 rounded-lg bg-cyan-500 text-black hover:bg-cyan-400 transition"
          >
            Nuevo escaneo
          </button>
        </div>
      </header>

      <main className="max-w-[1200px] mx-auto px-4 md:px-6 py-10">
        <div className="mb-5 flex items-center gap-3 px-4 py-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-400">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="text-cyan-400 shrink-0">
            <path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/>
            <polyline points="16 6 12 2 8 6"/>
            <line x1="12" y1="2" x2="12" y2="15"/>
          </svg>
          <span>Reporte compartido — almacenado localmente en este dispositivo</span>
        </div>
        <ThreatReport result={result} onNewScan={handleNewScan} />
      </main>
    </div>
  );
}
