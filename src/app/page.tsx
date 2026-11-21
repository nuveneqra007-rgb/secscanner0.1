"use client";
import { useEffect, useState } from "react";
import Image from "next/image";
import dynamic from "next/dynamic";
import { ScannerInput } from "@/components/ScannerInput";
import { ScanningProgress } from "@/components/ScanningProgress";
import { ThreatReport } from "@/components/ThreatReport";
import { HistoryPanel } from "@/components/HistoryPanel";
import { ScanResult } from "@/lib/types";
import { addScan, clearHistory, loadHistory } from "@/lib/storage";
import { detectIndicatorType } from "@/lib/utils";

// Carga del BootSequence solo en el cliente para evitar mismatch de hidratación con sessionStorage
const BootSequence = dynamic(
  () => import("@/components/BootSequence").then((mod) => mod.BootSequence),
  { ssr: false }
);

// ── FAB flotante de historial (móvil) ───────────────────────────────────────────
function HistoryFab({
  history,
  onSelect,
  selectedId,
}: {
  history: ScanResult[];
  onSelect: (r: ScanResult) => void;
  selectedId: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="lg:hidden fixed bottom-6 right-5 z-50 flex items-center gap-2 px-4 py-3 rounded-2xl bg-[#121212] border border-[#333333] shadow-2xl text-sm font-semibold text-white hover:bg-[#1A1A1A] transition print:hidden"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/>
        </svg>
        Historial
        <span className="ml-0.5 text-xs font-mono text-[#666666]">{history.length}</span>
      </button>

      {open && (
        <div className="lg:hidden fixed inset-0 z-50 flex flex-col justify-end print:hidden">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          />
          <div className="relative bg-[#0A0A0A] border-t border-[#333333] rounded-t-3xl max-h-[75vh] flex flex-col">
            <div className="flex justify-center pt-3 pb-1 shrink-0">
              <div className="w-10 h-1 rounded-full bg-[#333333]" />
            </div>
            <div className="px-4 pb-4 overflow-y-auto flex-1">
              <HistoryPanel
                history={history}
                onSelect={(r) => { onSelect(r); setOpen(false); }}
                onClear={() => {}}
                selectedId={selectedId}
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default function Home() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [pendingInput, setPendingInput] = useState<{ input: string; fileName?: string; fileBase64?: string } | null>(null);
  const [showInput, setShowInput] = useState(true);
  const [scanError, setScanError] = useState<string | null>(null);
  const [booted, setBooted] = useState(false);

  const indicatorKind = pendingInput
    ? (pendingInput.fileName?.toLowerCase().endsWith(".apk") ? "apk"
       : pendingInput.fileName ? "file"
       : detectIndicatorType(pendingInput.input))
    : "unknown";

  useEffect(() => {
    const timer = setTimeout(() => {
      setHistory(loadHistory());
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const startScan = (input: string, fileName?: string, fileBase64?: string) => {
    if (!input.trim()) return;
    setPendingInput({ input, fileName, fileBase64 });
    setScanning(true);
    setShowInput(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const completeScan = async () => {
    if (!pendingInput) return;
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          indicator: pendingInput.input,
          fileName: pendingInput.fileName,
          fileBase64: pendingInput.fileBase64,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => null);
        throw new Error(errData?.error || `Error en el análisis (${response.status})`);
      }

      const result: ScanResult = await response.json();
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
    <div className="min-h-screen flex flex-col bg-[#0A0A0A] text-white relative">

      {/* Boot Terminal Intro */}
      {!booted && <BootSequence onComplete={() => setBooted(true)} />}

      {/* CRT Scanline + Vignette Overlays */}
      <div className="crt-scanline" />
      <div className="vignette" />

      {/* Retro Wireframe Background Grid */}
      <div className="fixed inset-0 -z-10 bg-[linear-gradient(to_right,rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:48px_48px]" />

      {/* ── HEADER ── */}
      <header className="sticky top-0 z-40 backdrop-blur-xl bg-[#0A0A0A]/85 border-b border-[#333333]/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          {/* Logo y Nombre */}
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

          {/* Acciones */}
          <div className="flex items-center gap-2.5">
            <a
              href="https://github.com/nuveneqra007-rgb/secscanner0.1"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium px-3.5 py-2 rounded-lg bg-[#121212] border border-[#333333] text-[#A3A3A3] hover:bg-[#1A1A1A] hover:text-white transition"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.49.5.09.68-.22.68-.48v-1.69c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.56 9.56 0 0112 6.8c.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10.01 10.01 0 0022 12c0-5.52-4.48-10-10-10z"/></svg>
              Código
            </a>
            <button
              onClick={handleNewScan}
              className="text-xs font-bold px-4 py-2 rounded-lg bg-white text-black hover:bg-[#E0E0E0] transition neon-hover border border-transparent tracking-wider uppercase"
            >
              Nuevo escaneo
            </button>
          </div>
        </div>
      </header>

      {/* ── MAIN ── */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 md:py-16">

        {/* ── LANDING HERO (Estilo VirusTotal Centrado + Retro Wireframe) ── */}
        {showInput && !scanning && !selected && (
          <div className="flex flex-col items-center">

            {/* Logo Central Prominente y Nombre estilo VirusTotal */}
            <div className="animate-fade-up flex flex-col items-center mb-4">
              <div className="relative mb-3 group">
                <div className="w-20 h-20 sm:w-24 sm:h-24 rounded-2xl border border-[#333333] bg-[#121212] p-3 shadow-2xl flex items-center justify-center">
                  <Image
                    src="/logo.png"
                    alt="SecScanner"
                    width={80}
                    height={80}
                    className="object-contain filter contrast-125"
                    priority
                  />
                </div>
                <div className="absolute -inset-1 rounded-2xl bg-white/5 blur-md -z-10" />
              </div>

              <h1 className="text-[clamp(1.75rem,5vw,3rem)] font-black tracking-[0.2em] sm:tracking-[0.25em] text-center text-white mb-2">
                SECSCANNER
              </h1>
            </div>

            {/* Subtítulo estilo VirusTotal */}
            <p className="animate-fade-up delay-100 text-xs sm:text-sm md:text-[15px] font-mono text-[#A3A3A3] text-center max-w-[580px] leading-relaxed mb-10 px-2">
              Analiza archivos sospechosos, dominios, IPs y URLs para detectar malware y otras anomalías en tiempo real.
            </p>

            {/* Input Principal con Tabs estilo VirusTotal */}
            <div className="animate-fade-up delay-150 w-full mb-16">
              <ScannerInput onAnalyze={startScan} loading={false} />
            </div>

            {/* Separador */}
            <div className="w-full max-w-[800px] mb-10 flex items-center gap-4">
              <div className="h-px flex-1 bg-[#222222]" />
              <span className="text-[11px] font-mono tracking-[0.2em] text-[#666666] uppercase">Arquitectura del Escáner</span>
              <div className="h-px flex-1 bg-[#222222]" />
            </div>

            {/* Sección "Cómo funciona" con Líneas Conectoras SVG Animadas */}
            <div className="w-full max-w-[800px] mb-16 relative">
              {/* Línea conectora SVG animada en desktop */}
              <div className="hidden sm:block absolute top-[28px] left-[15%] right-[15%] h-[2px] -z-0 pointer-events-none">
                <svg className="w-full h-4 overflow-visible">
                  <line
                    x1="0"
                    y1="0"
                    x2="100%"
                    y2="0"
                    stroke="#444444"
                    strokeWidth="2"
                    strokeDasharray="6 6"
                    className="animate-pulse"
                  />
                </svg>
              </div>

              <div className="grid sm:grid-cols-3 gap-4 relative z-10">
                {[
                  {
                    step: "01",
                    title: "Ingesta y Detección",
                    desc: "Identificación de tipo de indicador (hash, IP, URL o APK), sanitización y normalización RFC.",
                  },
                  {
                    step: "02",
                    title: "Correlación Multi-fuente",
                    desc: "Análisis paralelo de WHOIS, DNS, TLS, entropía de Shannon, reglas YARA y reputación.",
                  },
                  {
                    step: "03",
                    title: "Reporte Accionable",
                    desc: "Puntuación de riesgo 0–100, veredicto, hallazgos por severidad e IoCs listos para SIEM.",
                  },
                ].map(({ step, title, desc }) => (
                  <div
                    key={step}
                    className="rounded-2xl bg-[#121212]/90 border border-[#333333] p-5 hover:border-white/40 transition-colors shadow-lg"
                  >
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center text-xs font-mono font-black mb-3 bg-[#1A1A1A] border border-[#333333] text-white">
                      {step}
                    </div>
                    <div className="text-sm font-semibold text-white mb-1.5">{title}</div>
                    <div className="text-xs text-[#888888] leading-relaxed font-mono">{desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Historial */}
            <div className="w-full max-w-[800px]">
              <HistoryPanel
                history={history}
                onSelect={handleSelect}
                onClear={handleClear}
                selectedId={undefined}
              />
            </div>

          </div>
        )}

        {/* ── ESCANEANDO EN PROGRESO ── */}
        {scanning && pendingInput && (
          <div className="flex flex-col items-center py-6">
            <div className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full bg-[#121212] border border-[#333333] text-sm font-mono text-[#A3A3A3] mb-8 shadow-md">
              <span className="w-2 h-2 bg-white rounded-full animate-ping" />
              <span className="text-[#666666]">Procesando:</span>
              <span className="text-white truncate max-w-[260px] sm:max-w-[420px]">
                {pendingInput.input.slice(0, 80)}
              </span>
            </div>

            <ScanningProgress onComplete={completeScan} indicatorKind={indicatorKind} />

            <div className="mt-8 max-w-[620px] rounded-2xl border border-[#333333] bg-[#121212]/80 p-5 text-center shadow-lg">
              <div className="text-[10px] font-mono tracking-widest text-[#666666] mb-2 uppercase">Heurística & Threat Intelligence</div>
              <p className="text-xs leading-relaxed text-[#888888] font-mono">
                El 70% de dominios maliciosos tienen menos de 30 días de vida. SecScanner analiza la edad WHOIS, la entropía del dominio y los bloques ASN para detectar infraestructura desechable antes de su inclusión en feeds estáticos.
              </p>
            </div>
          </div>
        )}

        {/* ── REPORTE GENERADO ── */}
        {selected && !scanning && (
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] xl:grid-cols-[2fr_1fr] gap-6 items-start w-full max-w-full">
            {/* Panel de Escaneo Rápido en Móvil/Tablet (< 1024px, arriba) */}
            <div className="block lg:hidden rounded-2xl border border-[#333333] bg-[#121212]/80 p-3.5 sm:p-4 shadow-xl w-full">
              <div className="text-[10px] font-bold tracking-widest text-[#666666] mb-2 sm:mb-3 uppercase font-mono">Escaneo Rápido</div>
              <ScannerInput onAnalyze={startScan} loading={false} compact={true} />
            </div>

            {/* Columna de Resultados (Izquierda en desktop) */}
            <div className="min-w-0 w-full max-w-full">
              <button
                onClick={handleNewScan}
                className="mb-4 sm:mb-5 inline-flex items-center gap-2 text-xs sm:text-sm font-medium px-3.5 sm:px-4 py-2 rounded-lg bg-[#121212] border border-[#333333] text-[#A3A3A3] hover:bg-[#1A1A1A] hover:text-white transition print:hidden"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M19 12H5" /><path d="M12 19l-7-7 7-7" />
                </svg>
                Volver al buscador
              </button>
              <ThreatReport result={selected} onNewScan={handleNewScan} />
            </div>

            {/* Sidebar Sticky en Desktop (>= 1024px) & Historial abajo en móvil */}
            <div className="lg:sticky lg:top-[76px] flex flex-col gap-4 w-full print:hidden">
              <div className="hidden lg:block rounded-2xl border border-[#333333] bg-[#121212]/80 p-4 shadow-xl">
                <div className="text-[10px] font-bold tracking-widest text-[#666666] mb-3 uppercase font-mono">Escaneo Rápido</div>
                <ScannerInput onAnalyze={startScan} loading={false} compact={true} />
              </div>
              <HistoryPanel
                history={history}
                onSelect={handleSelect}
                onClear={handleClear}
                selectedId={selected.id}
              />
            </div>
          </div>
        )}

        {/* FAB Historial en Móvil */}
        {selected && !scanning && history.length > 0 && (
          <HistoryFab history={history} onSelect={handleSelect} selectedId={selected.id} />
        )}

        {/* Estado Huérfano */}
        {!showInput && !selected && !scanning && !scanError && (
          <div className="max-w-[800px] mx-auto">
            <HistoryPanel history={history} onSelect={handleSelect} onClear={handleClear} />
          </div>
        )}

        {/* ── ERROR EN EL ESCANEO ── */}
        {scanError && (
          <div className="max-w-[560px] mx-auto flex flex-col items-center gap-5 py-10 text-center animate-glitch-in">
            <div className="w-14 h-14 rounded-2xl bg-[#FF3333]/10 border border-[#FF3333]/20 flex items-center justify-center text-[#FF3333]">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-bold text-white mb-2">Error en el análisis</h2>
              <p className="text-sm text-[#A3A3A3] leading-relaxed">
                No se pudo procesar el indicador. Verifica que el formato sea válido e inténtalo de nuevo.
              </p>
              <div className="mt-3 rounded-xl bg-[#121212] border border-[#333333] px-4 py-2.5 text-xs font-mono text-[#FF3333] text-left break-all">
                {scanError}
              </div>
            </div>
            <button
              onClick={handleNewScan}
              className="px-6 py-2.5 rounded-xl bg-white text-black font-bold text-sm tracking-wider uppercase hover:bg-[#E0E0E0] transition neon-hover border border-transparent"
            >
              Intentar de nuevo
            </button>
          </div>
        )}
      </main>

      {/* ── FOOTER ── */}
      <footer className="border-t border-[#1A1A1A] mt-12 bg-[#0A0A0A]">
        <div className="max-w-[1200px] mx-auto px-4 md:px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-[#666666]">
          <span>© 2025 SecScanner — Threat Intelligence Framework</span>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded-full bg-[#121212] border border-[#333333]">Historial en navegador · Sin tracking</span>
            <span className="px-2.5 py-1 rounded-full bg-[#121212] border border-[#333333]">MIT</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
