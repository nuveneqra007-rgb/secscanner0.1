"use client";
import { useEffect, useState } from "react";
import { ScannerInput } from "@/components/ScannerInput";
import { ScanningProgress } from "@/components/ScanningProgress";
import { ThreatReport } from "@/components/ThreatReport";
import { HistoryPanel } from "@/components/HistoryPanel";
import { analyze } from "@/lib/analyzer";
import { ScanResult } from "@/lib/types";
import { addScan, clearHistory, loadHistory } from "@/lib/storage";

export default function Home() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [pendingInput, setPendingInput] = useState<{ input: string; fileName?: string } | null>(null);
  const [showInput, setShowInput] = useState(true);

  useEffect(() => {
    const h = loadHistory();
    setHistory(h);
    // auto-select most recent
    if (h.length > 0 && !selected) {
      // don't auto-select, keep landing clean — but we want seed visible in history
    }
  }, []);

  const startScan = (input: string, fileName?: string) => {
    if (!input.trim()) return;
    setPendingInput({ input, fileName });
    setScanning(true);
    setShowInput(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const completeScan = () => {
    if (!pendingInput) return;
    const result = analyze(pendingInput.input, pendingInput.fileName);
    const nextHist = addScan(result);
    setHistory(nextHist);
    setSelected(result);
    setScanning(false);
    setPendingInput(null);
  };

  const handleSelect = (r: ScanResult) => {
    setSelected(r);
    setShowInput(false);
    setScanning(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleClear = () => {
    clearHistory();
    setHistory([]);
    setSelected(null);
  };

  const handleNewScan = () => {
    setSelected(null);
    setShowInput(true);
    setScanning(false);
    setPendingInput(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#09090b]">
      {/* subtle grid */}
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,#27272a_1px,transparent_1px),linear-gradient(to_bottom,#27272a_1px,transparent_1px)] bg-[size:32px_32px] opacity-[0.06]" />
      <div className="fixed inset-0 -z-10 bg-gradient-to-b from-cyan-950/10 via-transparent to-transparent" />

      {/* Header */}
      <header className="sticky top-0 z-40 backdrop-blur-xl bg-zinc-950/70 border-b border-zinc-800">
        <div className="max-w-[1200px] mx-auto px-5 md:px-6 h-[64px] flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-white flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#09090b" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
            </div>
            <div>
              <div className="text-sm font-black tracking-[0.18em] text-white">THREATSCAN</div>
              <div className="text-[11px] font-mono tracking-widest text-zinc-500 -mt-1">THREAT INTELLIGENCE LAB</div>
            </div>
            <span className="hidden lg:inline-flex ml-3 text-[10px] font-mono tracking-widest px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-500">v2.4 • Heurística + YARA</span>
          </div>

          <div className="flex items-center gap-2 md:gap-3">
            <div className="hidden md:flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">
              <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
              1,847 análisis hoy
            </div>
            <a href="https://github.com" target="_blank" className="hidden md:inline-flex text-xs font-medium px-3 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-300 hover:bg-zinc-800">Ver código →</a>
            <button onClick={handleNewScan} className="text-xs font-bold px-4 py-2 rounded-xl bg-cyan-500 text-black hover:bg-cyan-400 transition">Nuevo escaneo</button>
          </div>
        </div>
      </header>

      <main className="flex-1 w-full max-w-[1200px] mx-auto px-5 md:px-6 py-8 md:py-10">
        {/* Hero when no report */}
        {showInput && !scanning && !selected && (
          <>
            <div className="text-center max-w-[780px] mx-auto mb-8">
              <div className="inline-flex items-center gap-2 text-[11px] font-mono tracking-widest px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 mb-4">
                <span className="w-1.5 h-1.5 bg-amber-400 rounded-full animate-pulse" />
                DEMO INTERACTIVA — Sin registro • Resultados en 2s
              </div>
              <h1 className="text-4xl md:text-5xl font-black tracking-tighter text-white leading-[0.95]">
                ANALIZA AMENAZAS
                <span className="block text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-sky-400">EN SEGUNDOS</span>
              </h1>
              <p className="mt-4 text-sm md:text-[15px] leading-relaxed text-zinc-400 max-w-[560px] mx-auto">
                Pega una <span className="text-zinc-200 font-semibold">URL, IP o hash</span> y obtén un reporte técnico digno de un SOC. Heurística de phishing, reputación global y análisis de permisos APK.
              </p>
              <div className="mt-5 flex flex-wrap justify-center gap-2 text-[11px] font-mono">
                <span className="px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">✓ Typosquatting & Homoglyphs</span>
                <span className="px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">✓ AbuseIPDB & VT</span>
                <span className="px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">✓ 240 reglas YARA</span>
              </div>
            </div>

            <ScannerInput onAnalyze={startScan} loading={false} />

            {/* history below on landing */}
            <div className="max-w-[760px] mx-auto mt-8">
              <HistoryPanel history={history} onSelect={handleSelect} onClear={handleClear} selectedId={undefined} />
              <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-900/30 p-6">
                <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-3">¿CÓMO FUNCIONA?</h3>
                <div className="grid md:grid-cols-3 gap-4 text-xs leading-relaxed">
                  <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4">
                    <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-2">1</div>
                    <div className="font-semibold text-zinc-200">Ingesta & Normalización</div>
                    <div className="text-zinc-500 mt-1">Detección automática del indicador, decodificación y sanitización contra inyección.</div>
                  </div>
                  <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4">
                    <div className="w-8 h-8 rounded-lg bg-violet-500/15 border border-violet-500/20 flex items-center justify-center text-violet-400 mb-2">2</div>
                    <div className="font-semibold text-zinc-200">Correlación Multi-Fuente</div>
                    <div className="text-zinc-500 mt-1">WHOIS, DNS, TLS, blacklists, geolocalización y heurística en paralelo.</div>
                  </div>
                  <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4">
                    <div className="w-8 h-8 rounded-lg bg-emerald-500/15 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-2">3</div>
                    <div className="font-semibold text-zinc-200">Reporte Accionable</div>
                    <div className="text-zinc-500 mt-1">Score 0-100, severidades, IoCs y recomendaciones listas para tu SIEM.</div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Scanning */}
        {scanning && pendingInput && (
          <div className="py-8">
            <div className="text-center mb-8">
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-zinc-900 border border-zinc-800 text-sm font-mono text-zinc-300">
                <span className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
                Analizando: <span className="text-white truncate max-w-[280px] md:max-w-[420px]">{pendingInput.input.slice(0, 80)}</span>
              </div>
            </div>
            <ScanningProgress onComplete={completeScan} />
            <div className="mt-10 max-w-[640px] mx-auto rounded-2xl border border-zinc-800 bg-zinc-900/30 p-5">
              <div className="text-xs font-mono tracking-widest text-zinc-500 mb-2">¿SABÍAS QUE...?</div>
              <p className="text-sm leading-relaxed text-zinc-400">El 70% de dominios de phishing tienen menos de 30 días de antigüedad. Nuestro motor prioriza la edad WHOIS, la entropía del dominio y la reputación ASN para detectar campañas desechables antes que las listas negras.</p>
            </div>
          </div>
        )}

        {/* Report + Sidebar */}
        {selected && !scanning && (
          <div className="grid lg:grid-cols-[1fr_340px] gap-6 items-start">
            <div className="min-w-0">
              <button onClick={handleNewScan} className="mb-6 inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-300 hover:bg-zinc-800">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
                Volver al escáner
              </button>
              <ThreatReport result={selected} onNewScan={handleNewScan} />
            </div>

            <div className="lg:sticky lg:top-[80px] space-y-6">
              <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-5">
                <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-3">ESCANEO RÁPIDO</h3>
                <ScannerInput onAnalyze={startScan} loading={false} />
              </div>
              <HistoryPanel history={history} onSelect={handleSelect} onClear={handleClear} selectedId={selected.id} />
              <div className="rounded-2xl border border-cyan-900/50 bg-cyan-950/20 p-5">
                <div className="text-xs font-bold tracking-widest text-cyan-400">PARA RECLUTADORES</div>
                <p className="text-xs leading-relaxed text-zinc-300 mt-2">Esta herramienta demuestra: análisis heurístico, modelado de amenazas, UX para SOC y arquitectura Next.js sin backend. Código abierto y documentado.</p>
                <div className="mt-3 flex gap-2">
                  <span className="text-[11px] px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">Next.js 16</span>
                  <span className="text-[11px] px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">Tailwind</span>
                  <span className="text-[11px] px-2 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">TypeScript</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* When no selection but scanning not active and input hidden? Show history alone case */}
        {!showInput && !selected && !scanning && (
          <div className="max-w-[760px] mx-auto">
            <HistoryPanel history={history} onSelect={handleSelect} onClear={handleClear} />
          </div>
        )}
      </main>

      <footer className="border-t border-zinc-900 mt-8">
        <div className="max-w-[1200px] mx-auto px-5 md:px-6 py-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs font-mono text-zinc-500">
          <div>© 2026 ThreatScan Lab — Proyecto de portafolio. Hecho con Next.js, Tailwind & heurística.</div>
          <div className="flex items-center gap-3">
            <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">LocalStorage • Sin tracking</span>
            <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">MIT License</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
