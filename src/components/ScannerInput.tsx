"use client";
import { useRef, useState } from "react";
import { detectIndicatorType } from "@/lib/utils";

type Tab = "url" | "ip" | "hash" | "archivo";

const TABS: { id: Tab; label: string }[] = [
  { id: "url",     label: "URL / Dominio" },
  { id: "ip",      label: "IP" },
  { id: "hash",    label: "Hash" },
  { id: "archivo", label: "Archivo / APK" },
];

const VALIDATORS: Record<Tab, (v: string) => boolean> = {
  url:     (v) => v.length > 4 && /[a-z0-9.-]/i.test(v),
  ip:      (v) => /^[\d.:a-fA-F]+$/.test(v) && v.length >= 7,
  hash:    (v) => /^[a-fA-F0-9]{32,64}$/.test(v),
  archivo: () => false, // se valida por fileName
};

const PLACEHOLDERS: Record<Tab, string> = {
  url:     "https://ejemplo.com o dominio.xyz",
  ip:      "192.168.1.1 o 2001:db8::1",
  hash:    "MD5, SHA1 o SHA256 del archivo",
  archivo: "Arrastra un archivo o haz clic en Subir",
};

const EXAMPLES: Record<Tab, { label: string; value: string }[]> = {
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
  archivo: [],
};

export function ScannerInput({
  onAnalyze,
  loading,
}: {
  onAnalyze: (input: string, fileName?: string) => void;
  loading: boolean;
}) {
  const [tab, setTab] = useState<Tab>("url");
  const [value, setValue] = useState("");
  const [fileName, setFileName] = useState<string | undefined>();
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const detectedType = value.trim() ? detectIndicatorType(value.trim()) : null;
  const isFileTab = tab === "archivo";
  const isValid = isFileTab ? !!fileName : VALIDATORS[tab](value.trim());

  const handleAnalyze = () => {
    if (!isValid) return;
    onAnalyze(isFileTab ? (fileName ?? "") : value.trim(), fileName);
  };

  const handleFile = (f: File) => {
    setFileName(f.name);
    setValue(f.name);
  };

  const handleTabChange = (t: Tab) => {
    setTab(t);
    setValue("");
    setFileName(undefined);
  };

  return (
    <div className="w-full max-w-[760px] mx-auto">
      <div
        className={`rounded-2xl border bg-zinc-900/80 backdrop-blur shadow-2xl transition-colors ${
          dragOver ? "border-cyan-500/60 bg-cyan-500/5" : "border-zinc-800"
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files[0];
          if (f) { handleFile(f); setTab("archivo"); }
        }}
      >
        {/* ── Tabs ── */}
        <div className="flex border-b border-zinc-800 px-2 pt-2 gap-1 overflow-x-auto">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => handleTabChange(t.id)}
              className={`px-4 py-2.5 text-xs font-bold tracking-wider rounded-t-lg transition-colors whitespace-nowrap
                ${tab === t.id
                  ? "bg-zinc-800 text-white border border-b-0 border-zinc-700"
                  : "text-zinc-500 hover:text-zinc-300"
                }`}
            >
              {t.label}
            </button>
          ))}
          {/* Estado del motor */}
          <div className="ml-auto self-center pr-2 hidden sm:flex items-center gap-1.5 text-[11px] font-mono text-zinc-500 shrink-0">
            <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
            Motor en línea
          </div>
        </div>

        {/* ── Cuerpo ── */}
        <div className="p-5 md:p-6">
          {/* Input principal */}
          {!isFileTab ? (
            <div className="relative">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                  <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                </svg>
              </div>
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                placeholder={PLACEHOLDERS[tab]}
                className="w-full pl-11 pr-[130px] h-14 rounded-xl bg-zinc-950 border border-zinc-800 text-[15px] text-white placeholder:text-zinc-600 focus:outline-none focus:border-cyan-500/60 focus:ring-4 focus:ring-cyan-500/10 transition"
              />
              <button
                onClick={handleAnalyze}
                disabled={loading || !isValid}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 h-11 px-5 rounded-lg bg-cyan-500 text-black text-sm font-bold hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 transition"
              >
                {loading ? (
                  <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                ) : (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <path d="M22 2L11 13" /><path d="M22 2L15 22L11 13L2 9L22 2Z" />
                  </svg>
                )}
                Analizar
              </button>
            </div>
          ) : (
            /* ── Zona de archivo ── */
            <div
              onClick={() => fileRef.current?.click()}
              className={`h-28 rounded-xl border-2 border-dashed flex flex-col items-center justify-center gap-2 cursor-pointer transition-colors
                ${dragOver ? "border-cyan-500/60 bg-cyan-500/5" : "border-zinc-700 hover:border-zinc-500 hover:bg-zinc-800/40"}`}
            >
              {fileName ? (
                <>
                  <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                    </svg>
                  </div>
                  <span className="text-sm font-medium text-zinc-200">{fileName}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFileName(undefined); setValue(""); }}
                    className="text-xs text-zinc-500 hover:text-zinc-300 underline"
                  >
                    Quitar
                  </button>
                </>
              ) : (
                <>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#52525b" strokeWidth="1.6">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                  <span className="text-sm text-zinc-500">Arrastra un archivo o <span className="text-zinc-300 underline">haz clic aquí</span></span>
                  <span className="text-xs font-mono text-zinc-600">APK · ZIP · EXE · PDF · JS</span>
                </>
              )}
            </div>
          )}

          <input
            ref={fileRef}
            type="file"
            className="hidden"
            accept=".apk,.zip,.exe,.pdf,.js,*/*"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />

          {/* Hint de formato inválido */}
          {value.trim().length > 3 && !isFileTab && !VALIDATORS[tab](value.trim()) && (
            <div className="mt-2 flex items-center gap-2 text-xs font-mono text-amber-400">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              {tab === "ip"   && "Formato esperado: 192.168.1.1 o dirección IPv6"}
              {tab === "hash" && "Formato esperado: 32, 40 o 64 caracteres hexadecimales"}
              {tab === "url"  && "Introduce una URL o dominio válido"}
            </div>
          )}

          {/* Tipo detectado */}
          {detectedType && value && !isFileTab && (
            <div className="mt-3 flex items-center gap-2 text-xs font-mono">
              <span className="text-zinc-600">Detectado:</span>
              <span className="px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-bold tracking-widest">
                {detectedType.toUpperCase()}
              </span>
            </div>
          )}

          {/* Botón analizar para tab archivo */}
          {isFileTab && fileName && (
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="mt-4 w-full h-12 rounded-xl bg-cyan-500 text-black font-bold text-sm hover:bg-cyan-400 disabled:opacity-40 transition flex items-center justify-center gap-2"
            >
              {loading
                ? <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                : "Analizar archivo"
              }
            </button>
          )}

          {/* Ejemplos */}
          {EXAMPLES[tab].length > 0 && (
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <span className="text-[11px] text-zinc-600 font-mono">Ejemplos:</span>
              {EXAMPLES[tab].map((ex) => (
                <button
                  key={ex.value}
                  onClick={() => setValue(ex.value)}
                  className="text-[11px] font-mono px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 hover:bg-zinc-700 hover:text-white transition"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}

          {/* Badges de garantías */}
          <div className="mt-5 pt-4 border-t border-zinc-800/60 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] font-mono text-zinc-600">
            <span>✓ Sin registro</span>
            <span>✓ 100% local · sin servidor</span>
            <span>✓ Heurística + YARA</span>
            <span>✓ Resultados en ~2s</span>
          </div>
        </div>
      </div>

      {/* Capacidades por tipo */}
      <div className="mt-3 grid grid-cols-3 gap-2.5">
        {[
          { type: "URL",  desc: "Typosquatting · homoglyphs · SSL · redirecciones" },
          { type: "IP",   desc: "AbuseIPDB · geolocalización · puertos · Tor" },
          { type: "APK",  desc: "Permisos · hashes · VirusTotal · YARA" },
        ].map(({ type, desc }) => (
          <div key={type} className="rounded-xl bg-zinc-900/40 border border-zinc-800 px-4 py-3">
            <div className="text-[10px] font-black tracking-widest text-zinc-400 mb-1">{type}</div>
            <div className="text-[11px] text-zinc-600 leading-relaxed">{desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
