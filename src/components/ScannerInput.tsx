"use client";
import { useRef, useState } from "react";
import { detectIndicatorType } from "@/lib/utils";

type Tab = "archivo" | "url" | "ip" | "hash";

const TABS: { id: Tab; label: string }[] = [
  { id: "archivo", label: "ARCHIVO / APK" },
  { id: "url",     label: "URL" },
  { id: "ip",      label: "IP" },
  { id: "hash",    label: "HASH" },
];

const VALIDATORS: Record<Tab, (v: string) => boolean> = {
  archivo: () => false,
  url:     (v) => v.length > 4 && /[a-z0-9.-]/i.test(v),
  ip:      (v) => /^[\d.:a-fA-F]+$/.test(v) && v.length >= 7,
  hash:    (v) => /^[a-fA-F0-9]{32,64}$/.test(v),
};

const PLACEHOLDERS: Record<Tab, string> = {
  archivo: "Arrastra un archivo o haz clic en Seleccionar",
  url:     "https://ejemplo.com o dominio.xyz",
  ip:      "8.8.8.8 o 185.220.101.47",
  hash:    "MD5, SHA1 o SHA256 (32, 40 o 64 caracteres hex)",
};

const EXAMPLES: Record<Tab, { label: string; value: string }[]> = {
  archivo: [],
  url: [
    { label: "Phishing bancario", value: "https://banc0-santander-secure-login.tk/verify/account?session=9283" },
    { label: "URL limpia",        value: "https://github.com/trending" },
  ],
  ip: [
    { label: "Tor exit node",   value: "185.220.101.47" },
    { label: "DNS público",     value: "8.8.8.8" },
  ],
  hash: [
    { label: "Hash MD5",    value: "e99a18c428cb38d5f260853678922e03" },
    { label: "Hash SHA256", value: "a3f5b2c1d4e6f7890123456789abcdef0123456789abcdef0123456789abcdef" },
  ],
};

export function ScannerInput({
  onAnalyze,
  loading,
  compact = false,
}: {
  onAnalyze: (input: string, fileName?: string, fileBase64?: string) => void;
  loading: boolean;
  compact?: boolean;
}) {
  const [tab, setTab] = useState<Tab>("archivo");
  const [value, setValue] = useState("");
  const [fileName, setFileName] = useState<string | undefined>();
  const [fileBase64, setFileBase64] = useState<string | undefined>();
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const detectedType = value.trim() ? detectIndicatorType(value.trim()) : null;
  const isFileTab = tab === "archivo";
  const isValid = isFileTab ? !!fileName : VALIDATORS[tab](value.trim());

  const handleAnalyze = () => {
    if (!isValid) return;
    onAnalyze(isFileTab ? (fileName ?? "") : value.trim(), fileName, fileBase64);
  };

  const handleFile = (f: File) => {
    setFileName(f.name);
    setValue(f.name);
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const b64 = result.split(",")[1];
      setFileBase64(b64);
    };
    reader.readAsDataURL(f);
  };

  const handleTabChange = (t: Tab) => {
    setTab(t);
    setValue("");
    setFileName(undefined);
    setFileBase64(undefined);
  };

  return (
    <div className="w-full max-w-[800px] mx-auto box-border">
      {/* ── Tabs estilo VirusTotal ── */}
      <div className={`flex justify-center border-b border-[#333333] relative overflow-x-auto scrollbar-none ${compact ? "mb-4" : "mb-6"}`}>
        <div className={`flex ${compact ? "gap-2 sm:gap-4 w-full justify-between" : "gap-4 sm:gap-10"}`}>
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => handleTabChange(t.id)}
              className={`pb-2.5 font-mono uppercase relative transition-colors duration-200 whitespace-nowrap ${
                compact ? "text-[11px] sm:text-xs tracking-wider" : "text-xs sm:text-sm tracking-[0.2em]"
              } ${
                tab === t.id ? "text-white font-bold" : "text-[#666666] hover:text-[#A3A3A3]"
              }`}
            >
              {compact && t.id === "archivo" ? "ARCHIVO" : t.label}
              {tab === t.id && (
                <span className="absolute bottom-[-1px] left-0 right-0 h-[2px] bg-white shadow-[0_0_10px_rgba(255,255,255,0.8)]" />
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ── Caja Principal ── */}
      <div
        className={`rounded-2xl border transition-all duration-300 relative overflow-hidden box-border max-w-full ${
          compact ? "p-3 sm:p-4 bg-[#0E0E0E]" : "p-4 sm:p-6 md:p-8 bg-[#121212]/90 backdrop-blur shadow-2xl"
        } ${
          dragOver ? "border-white bg-[#1A1A1A] shadow-[0_0_30px_rgba(255,255,255,0.15)]" : "border-[#333333]"
        }`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files[0];
          if (f) {
            handleFile(f);
            setTab("archivo");
          }
        }}
      >
        {/* TAB ARCHIVO / APK (Estilo VirusTotal con Icono Central y Láser de Escaneo) */}
        {isFileTab ? (
          <div className={`flex flex-col items-center justify-center text-center ${compact ? "py-2" : "py-6"}`}>
            {/* Icono de Archivo / Huella Digital con Línea de Escaneo Animada */}
            <div
              onClick={() => fileRef.current?.click()}
              className={`relative cursor-pointer group flex items-center justify-center ${compact ? "w-20 h-24 mb-3" : "w-28 h-32 mb-6"}`}
            >
              <div className={`rounded-xl border-2 border-[#444444] group-hover:border-white transition-colors bg-[#0A0A0A] flex flex-col items-center justify-center relative overflow-hidden shadow-inner ${compact ? "w-18 h-22" : "w-24 h-28"}`}>
                {/* Fingerprint / Scan Graphic */}
                <svg
                  width={compact ? "32" : "44"}
                  height={compact ? "32" : "44"}
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.2"
                  className="text-[#888888] group-hover:text-white transition-colors"
                >
                  <path d="M12 2a10 10 0 0 0-10 10c0 3.3 1.6 6.2 4.1 8" />
                  <path d="M12 6a6 6 0 0 0-6 6c0 1.9.9 3.6 2.3 4.7" />
                  <path d="M12 10a2 2 0 0 0-2 2c0 .8.4 1.5 1 1.8" />
                  <path d="M12 2v20" />
                  <path d="M16 6a6 6 0 0 1 2 4.3" />
                  <path d="M18 14c-.3 2.1-1.6 3.9-3.4 4.8" />
                </svg>

                {/* Laser scanline horizontal que cruza el icono */}
                <div
                  className="absolute left-0 right-0 h-[2px] bg-white shadow-[0_0_8px_#ffffff] pointer-events-none"
                  style={{ animation: "scanSweep 2.2s ease-in-out infinite" }}
                />
              </div>
            </div>

            {/* Nombre del archivo seleccionado o Call-to-action */}
            {fileName ? (
              <div className="flex flex-col items-center gap-3">
                <div className="px-4 py-2 rounded-xl bg-[#1A1A1A] border border-[#444444] flex items-center gap-3">
                  <span className="text-sm font-mono text-white max-w-[280px] sm:max-w-[420px] truncate">
                    {fileName}
                  </span>
                  <button
                    onClick={() => {
                      setFileName(undefined);
                      setValue("");
                    }}
                    className="text-xs text-[#888888] hover:text-[#FF3333] font-mono transition"
                  >
                    ✕ Quitar
                  </button>
                </div>
                <button
                  onClick={handleAnalyze}
                  disabled={loading}
                  className="mt-3 px-8 h-12 rounded-xl bg-white text-black font-bold text-sm tracking-wider uppercase hover:bg-[#E0E0E0] transition neon-hover shadow-lg flex items-center gap-2 border border-transparent"
                >
                  {loading ? (
                    <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                  ) : (
                    "Confirmar y Analizar Archivo"
                  )}
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center">
                <button
                  onClick={() => fileRef.current?.click()}
                  className="px-8 h-12 rounded-xl bg-white text-black font-bold text-sm tracking-wider uppercase hover:bg-[#E0E0E0] transition neon-hover shadow-lg flex items-center gap-2 border border-transparent mb-3"
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                  Elegir archivo
                </button>
                <p className="text-xs text-[#888888] font-mono mt-1">
                  o arrastra y suelta tu archivo en esta zona
                </p>
                <div className="mt-4 flex flex-wrap justify-center gap-2 text-[10px] font-mono text-[#555555]">
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">APK</span>
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">ZIP</span>
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">EXE</span>
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">PDF</span>
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">JS</span>
                  <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#262626]">ELF</span>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* TABS DE BÚSQUEDA (URL / IP / HASH) */
          <div className="w-full">
            <div className={`flex ${compact ? "flex-col" : "flex-col sm:flex-row"} items-stretch gap-2.5 w-full`}>
              <div className="relative flex-1 w-full min-w-0">
                <div className="absolute left-3.5 sm:left-4 top-1/2 -translate-y-1/2 text-[#666666] pointer-events-none">
                  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8" />
                    <path d="m21 21-4.35-4.35" />
                  </svg>
                </div>
                <input
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                  placeholder={PLACEHOLDERS[tab]}
                  className="w-full pl-10 sm:pl-11 pr-3 sm:pr-4 h-12 rounded-xl bg-[#0A0A0A] border border-[#333333] text-xs sm:text-sm font-mono text-white placeholder:text-[#444444] focus:outline-none focus:border-white focus:ring-2 focus:ring-white/10 transition box-border"
                />
              </div>
              <button
                onClick={handleAnalyze}
                disabled={loading || !isValid}
                className="h-12 px-5 sm:px-6 rounded-xl bg-white text-black text-xs sm:text-sm font-bold tracking-wider uppercase hover:bg-[#E0E0E0] disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition neon-hover border border-transparent shrink-0 whitespace-nowrap"
              >
                {loading ? (
                  <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                ) : (
                  <>
                    <span>Analizar</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M5 12h14" />
                      <path d="m12 5 7 7-7 7" />
                    </svg>
                  </>
                )}
              </button>
            </div>

            {/* Error de validación */}
            {value.trim().length > 3 && !VALIDATORS[tab](value.trim()) && (
              <div className="mt-2.5 flex items-center gap-2 text-xs font-mono text-[#FF3333] break-words">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <span>
                  {tab === "ip" && "Formato esperado: 192.168.1.1 o dirección IPv6"}
                  {tab === "hash" && "Formato esperado: 32 (MD5), 40 (SHA-1) o 64 (SHA-256) caracteres hex"}
                  {tab === "url" && "Introduce una URL o dominio válido"}
                </span>
              </div>
            )}

            {/* Tipo detectado */}
            {detectedType && value && (
              <div className="mt-3 flex items-center gap-2 text-xs font-mono">
                <span className="text-[#666666]">Tipo detectado:</span>
                <span className="px-2.5 py-0.5 rounded-full bg-white/10 border border-white/20 text-white font-bold tracking-widest">
                  {detectedType.toUpperCase()}
                </span>
              </div>
            )}

            {/* Ejemplos de consulta */}
            {EXAMPLES[tab].length > 0 && (
              <div className="mt-4 pt-3 border-t border-[#222222] flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-[#666666] font-mono">Ejemplos:</span>
                {EXAMPLES[tab].map((ex) => (
                  <button
                    key={ex.value}
                    onClick={() => setValue(ex.value)}
                    className="text-[10px] sm:text-[11px] font-mono px-2.5 sm:px-3 py-1 rounded-full bg-[#1A1A1A] border border-[#333333] text-[#A3A3A3] hover:border-white hover:text-white transition"
                  >
                    {ex.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <input
          ref={fileRef}
          type="file"
          className="hidden"
          accept=".apk,.zip,.exe,.pdf,.js,*/*"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
          }}
        />

        {/* Disclaimer inferior estilo VirusTotal (oculto en modo compacto de barra lateral) */}
        {!compact && (
          <div className="mt-6 pt-4 border-t border-[#222222] text-center">
            <p className="text-[11px] text-[#666666] font-mono leading-relaxed">
              Al analizar datos, el motor ejecuta heurística, entropía y correlación en un entorno local seguro.
              <br className="hidden sm:inline" /> Tus consultas no se comparten ni persisten en bases de datos externas.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
