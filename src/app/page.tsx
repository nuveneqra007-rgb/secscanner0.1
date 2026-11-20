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
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setHistory(loadHistory());
    }, 0);
    return () => clearTimeout(timer);
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
    try {
      const result = analyze(pendingInput.input, pendingInput.fileName);
      const nextHist = addScan(result);
      setHistory(nextHist);
      setSelected(result);
      setScanning(false);
      setPendingInput(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Error desconocido";
      setScanError(msg);
      setScanning(false);
      setPendingInput(null);
    }
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
    setScanError(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#09090b]">
      {/* Fondo: grid sutil + gradiente superior */}
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,#27272a_1px,transparent_1px),linear-gradient(to_bottom,#27272a_1px,transparent_1px)] bg-[size:32px_32px] opacity-[0.05]" />
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(ellipse_80%_40%_at_50%_-10%,rgba(6,182,212,0.08),transparent)]" />

      {/* ── HEADER ── */}
      <header className="sticky top-0 z-40 backdrop-blur-xl bg-zinc-950/80 border-b border-zinc-800/60">
        <div className="max-w-[1200px] mx-auto px-4 md:px-6 h-16 flex items-center justify-between gap-4">
          {/* Logo */}
          <button onClick={handleNewScan} className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg bg-cyan-500 flex items-center justify-center shrink-0 group-hover:bg-cyan-400 transition">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#09090b" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <div className="leading-none">
              <div className="text-[13px] font-black tracking-[0.15em] text-white">THREATSCAN</div>
              <div className="text-[10px] font-mono tracking-widest text-zinc-500 mt-0.5">THREAT INTELLIGENCE</div>
            </div>
          </button>

          {/* Estado del motor */}
          <div className="hidden md:flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800">
            <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
            Motor en línea
          </div>

          {/* Acciones */}
          <div className="flex items-center gap-2">
            <a
              href="https://github.com/nuveneqra007-rgb/secscanner0.1"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:bg-zinc-800 transition"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.49.5.09.68-.22.68-.48v-1.69c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.56 9.56 0 0112 6.8c.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10.01 10.01 0 0022 12c0-5.52-4.48-10-10-10z"/></svg>
              Código
            </a>
            <button
              onClick={handleNewScan}
              className="text-xs font-bold px-4 py-2 rounded-lg bg-cyan-500 text-black hover:bg-cyan-400 transition"
            >
              Nuevo escaneo
            </button>
          </div>
        </div>
      </header>

      {/* ── MAIN ── */}
      <main className="flex-1 w-full max-w-[1200px] mx-auto px-4 md:px-6 py-10 md:py-14">

        {/* ── LANDING: hero + input ── */}
        {showInput && !scanning && !selected && (
          <div className="flex flex-col items-center">
            {/* Pill de estado */}
            <div className="inline-flex items-center gap-2 text-[11px] font-mono tracking-widest px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400 mb-6">
              <span className="w-1.5 h-1.5 bg-amber-400 rounded-full animate-pulse" />
              Demo · Sin registro · 100% local
            </div>

            {/* Título */}
            <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tighter text-center leading-[0.92] mb-4">
              <span className="text-white">Detecta amenazas</span>
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-sky-400">en segundos</span>
            </h1>

            {/* Subtítulo */}
            <p className="text-sm md:text-[15px] text-zinc-400 text-center max-w-[480px] leading-relaxed mb-10">
              Pega una <span className="text-zinc-200 font-medium">URL, IP, dominio o hash</span> y obtén un reporte técnico completo: reputación, DNS, TLS, YARA y más.
            </p>

            {/* Input principal */}
            <ScannerInput onAnalyze={startScan} loading={false} />

            {/* Separador */}
            <div className="w-full max-w-[760px] mt-12 mb-8 flex items-center gap-4">
              <div className="h-px flex-1 bg-zinc-800" />
              <span className="text-[11px] font-mono tracking-widest text-zinc-600">CÓMO FUNCIONA</span>
              <div className="h-px flex-1 bg-zinc-800" />
            </div>

            {/* Pasos */}
            <div className="w-full max-w-[760px] grid sm:grid-cols-3 gap-3 mb-12">
              {[
                {
                  step: "01",
                  color: "cyan",
                  title: "Ingesta y detección",
                  desc: "Detecta automáticamente el tipo de indicador y sanitiza la entrada.",
                },
                {
                  step: "02",
                  color: "violet",
                  title: "Correlación multi-fuente",
                  desc: "WHOIS, DNS, TLS, reputación global y heurística en paralelo.",
                },
                {
                  step: "03",
                  color: "emerald",
                  title: "Reporte accionable",
                  desc: "Score 0–100, severidades, IoCs y recomendaciones para tu SIEM.",
                },
              ].map(({ step, color, title, desc }) => (
                <div key={step} className="rounded-2xl bg-zinc-900/40 border border-zinc-800 p-5">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-black mb-3
                    ${color === "cyan" ? "bg-cyan-500/15 border border-cyan-500/20 text-cyan-400" :
                      color === "violet" ? "bg-violet-500/15 border border-violet-500/20 text-violet-400" :
                      "bg-emerald-500/15 border border-emerald-500/20 text-emerald-400"}`}>
                    {step}
                  </div>
                  <div className="text-sm font-semibold text-zinc-200 mb-1">{title}</div>
                  <div className="text-xs text-zinc-500 leading-relaxed">{desc}</div>
                </div>
              ))}
            </div>

            {/* Historial */}
            <div className="w-full max-w-[760px]">
              <HistoryPanel
                history={history}
                onSelect={handleSelect}
                onClear={handleClear}
                selectedId={undefined}
              />
            </div>
          </div>
        )}

        {/* ── ESCANEANDO ── */}
        {scanning && pendingInput && (
          <div className="flex flex-col items-center py-6">
            {/* Indicador analizado */}
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-zinc-900 border border-zinc-800 text-sm font-mono text-zinc-300 mb-8">
              <span className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
              <span className="text-zinc-500">Analizando:</span>
              <span className="text-white truncate max-w-[260px] sm:max-w-[400px]">
                {pendingInput.input.slice(0, 80)}
              </span>
            </div>

            <ScanningProgress onComplete={completeScan} />

            {/* Dato educativo */}
            <div className="mt-8 max-w-[560px] rounded-2xl border border-zinc-800 bg-zinc-900/30 p-5 text-center">
              <div className="text-[10px] font-mono tracking-widest text-zinc-600 mb-2">¿SABÍAS QUE?</div>
              <p className="text-xs leading-relaxed text-zinc-400">
                El 70% de dominios de phishing tienen menos de 30 días de antigüedad. ThreatScan prioriza la edad WHOIS, la entropía del dominio y el ASN para detectar campañas desechables antes de que aparezcan en las listas negras.
              </p>
            </div>
          </div>
        )}

        {/* ── REPORTE ── */}
        {selected && !scanning && (
          <div className="grid lg:grid-cols-[1fr_320px] gap-6 items-start">
            {/* Reporte principal */}
            <div className="min-w-0">
              <button
                onClick={handleNewScan}
                className="mb-5 inline-flex items-center gap-2 text-sm font-medium px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:bg-zinc-800 transition"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M19 12H5" /><path d="M12 19l-7-7 7-7" />
                </svg>
                Volver
              </button>
              <ThreatReport result={selected} onNewScan={handleNewScan} />
            </div>

            {/* Sidebar — sticky en desktop, apilado en móvil */}
            <div className="lg:sticky lg:top-[76px] flex flex-col gap-4">
              {/* Escaneo rápido — oculto en móvil (el botón "Nuevo análisis" del reporte lo cubre) */}
              <div className="hidden lg:block rounded-2xl border border-zinc-800 bg-zinc-900/50 p-4">
                <div className="text-[10px] font-bold tracking-widest text-zinc-500 mb-3">ESCANEO RÁPIDO</div>
                <ScannerInput onAnalyze={startScan} loading={false} />
              </div>
              {/* Historial */}
              <HistoryPanel
                history={history}
                onSelect={handleSelect}
                onClear={handleClear}
                selectedId={selected.id}
              />
            </div>
          </div>
        )}

        {/* Estado huérfano: sin input, sin selección, sin escaneo */}
        {!showInput && !selected && !scanning && !scanError && (
          <div className="max-w-[760px] mx-auto">
            <HistoryPanel history={history} onSelect={handleSelect} onClear={handleClear} />
          </div>
        )}

        {/* ── ERROR ── */}
        {scanError && (
          <div className="max-w-[560px] mx-auto flex flex-col items-center gap-5 py-10 text-center">
            <div className="w-14 h-14 rounded-2xl bg-red-500/15 border border-red-500/20 flex items-center justify-center text-red-400">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-bold text-white mb-2">Error en el análisis</h2>
              <p className="text-sm text-zinc-400 leading-relaxed">
                No se pudo procesar el indicador. Verifica que el formato sea válido e inténtalo de nuevo.
              </p>
              <div className="mt-3 rounded-xl bg-zinc-900 border border-zinc-800 px-4 py-2.5 text-xs font-mono text-red-400 text-left break-all">
                {scanError}
              </div>
            </div>
            <button
              onClick={handleNewScan}
              className="px-6 py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-sm hover:bg-cyan-400 transition"
            >
              Intentar de nuevo
            </button>
          </div>
        )}
      </main>

      {/* ── FOOTER ── */}
      <footer className="border-t border-zinc-900 mt-6">
        <div className="max-w-[1200px] mx-auto px-4 md:px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-zinc-600">
          <span>© 2025 ThreatScan — Proyecto de portafolio · Next.js · Tailwind · TypeScript</span>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">LocalStorage · Sin tracking</span>
            <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">MIT</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
