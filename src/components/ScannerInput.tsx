"use client";
import { useRef, useState } from "react";
import { detectIndicatorType } from "@/lib/utils";

export function ScannerInput({ onAnalyze, loading }: { onAnalyze: (input: string, fileName?: string) => void; loading: boolean }) {
  const [value, setValue] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState<string | undefined>();

  const type = value.trim() ? detectIndicatorType(value.trim()) : null;
  const isValid = value.trim().length > 3 || !!fileName;

  const handleAnalyze = () => {
    if (!isValid) return;
    onAnalyze(value.trim() || fileName || "", fileName);
  };

  const handleFile = (f: File) => {
    setFileName(f.name);
    // For APK we set value to file name for display, but keep actual file name
    setValue(f.name);
    // Also read as text if small hash file? Just trigger analyze with filename
  };

  return (
    <div className="w-full max-w-[760px] mx-auto">
      <div className={`rounded-[24px] border bg-zinc-900/70 backdrop-blur p-6 md:p-8 shadow-2xl transition ${dragOver ? "border-cyan-500/50 bg-cyan-500/5" : "border-zinc-800"}`}
        onDragOver={e=>{e.preventDefault(); setDragOver(true);}}
        onDragLeave={()=> setDragOver(false)}
        onDrop={e=>{
          e.preventDefault(); setDragOver(false);
          const f = e.dataTransfer.files[0];
          if (f) handleFile(f);
        }}
      >
        {/* Tabs hint */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex gap-2">
            <span className="text-[11px] tracking-widest font-bold px-3 py-1.5 rounded-full bg-white text-black">URL</span>
            <span className="text-[11px] tracking-widest font-bold px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-400">IP</span>
            <span className="text-[11px] tracking-widest font-bold px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-400">ARCHIVO / HASH</span>
          </div>
          <span className="hidden md:inline-flex text-[11px] font-mono px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">● Motor en línea</span>
        </div>

        <div className="relative">
          <div className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          </div>
          <input
            value={value}
            onChange={e=> setValue(e.target.value)}
            onKeyDown={e=> e.key==="Enter" && handleAnalyze()}
            placeholder="Pega una URL, IP, dominio o hash (MD5/SHA256)…"
            className="w-full pl-12 pr-[140px] h-[56px] rounded-2xl bg-zinc-950 border border-zinc-800 text-[15px] text-white placeholder:text-zinc-500 focus:outline-none focus:border-cyan-500/50 focus:ring-4 focus:ring-cyan-500/10 transition"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading || !isValid}
            className="absolute right-1.5 top-1/2 -translate-y-1/2 h-[44px] px-6 rounded-xl bg-white text-black text-sm font-bold hover:bg-zinc-100 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition"
          >
            {loading ? <span className="w-4 h-4 border-2 border-zinc-400 border-t-black rounded-full animate-spin" /> : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg>}
            Analizar
          </button>
        </div>

        {type && value && (
          <div className="mt-3 flex items-center gap-2 text-xs font-mono">
            <span className="text-zinc-500">Detectado:</span>
            <span className="px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-bold tracking-widest">{type.toUpperCase()}</span>
            <span className="text-zinc-600 hidden sm:inline">• Auto-detección heurística</span>
          </div>
        )}

        <div className="mt-4 flex items-center gap-3">
          <div className="h-px flex-1 bg-zinc-800" />
          <span className="text-[11px] tracking-widest text-zinc-500 font-mono">O ARRASTRA UN ARCHIVO</span>
          <div className="h-px flex-1 bg-zinc-800" />
        </div>

        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button onClick={()=> fileRef.current?.click()} className="h-[52px] rounded-xl bg-zinc-950 border border-zinc-800 hover:border-zinc-700 flex items-center justify-center gap-2 text-sm font-medium text-zinc-300 transition">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Subir APK / Archivo
          </button>
          <button onClick={()=> setValue("8.8.8.8")} className="h-[52px] rounded-xl bg-zinc-950 border border-zinc-800 hover:border-zinc-700 text-sm font-mono text-zinc-400 transition">Ejemplo IP</button>
          <button onClick={()=> setValue("e99a18c428cb38d5f260853678922e03")} className="h-[52px] rounded-xl bg-zinc-950 border border-zinc-800 hover:border-zinc-700 text-sm font-mono text-zinc-400 transition">Ejemplo HASH</button>
        </div>
        <input ref={fileRef} type="file" className="hidden" accept=".apk,.zip,.exe,.pdf,.js,*/*" onChange={e=> { const f=e.target.files?.[0]; if (f) handleFile(f); }} />

        {fileName && (
          <div className="mt-3 rounded-xl bg-amber-500/10 border border-amber-500/20 px-4 py-3 flex items-center justify-between">
            <span className="text-sm font-medium text-amber-300">Archivo: {fileName}</span>
            <button onClick={()=>{ setFileName(undefined); setValue(""); }} className="text-xs text-amber-400 hover:text-amber-300">Quitar</button>
          </div>
        )}

        <div className="mt-5 flex flex-wrap gap-2">
          <span className="text-xs text-zinc-500 py-1">Prueba con:</span>
          {[
            "https://banc0-santander-secure-login.tk/verify/account?session=9283",
            "185.220.101.47",
            "https://github.com/trending",
          ].map(ex=>(
            <button key={ex} onClick={()=> setValue(ex)} className="text-xs font-mono px-3 py-1.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 hover:bg-zinc-700 hover:text-white transition truncate max-w-[320px]">
              {ex}
            </button>
          ))}
        </div>

        <div className="mt-6 flex flex-wrap gap-2 text-[11px] font-mono text-zinc-500">
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">✓ Sin registro</span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">✓ Sin base de datos</span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">✓ 100% local & privado</span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">✓ Heurística + YARA</span>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-3 max-w-[760px] mx-auto">
        <div className="rounded-2xl bg-zinc-900/40 border border-zinc-800 p-4">
          <div className="text-xs font-bold tracking-widest text-zinc-400">URLs</div>
          <div className="text-xs text-zinc-500 mt-1 leading-relaxed">Typosquatting, homoglyphs, redirecciones, SSL</div>
        </div>
        <div className="rounded-2xl bg-zinc-900/40 border border-zinc-800 p-4">
          <div className="text-xs font-bold tracking-widest text-zinc-400">IPs</div>
          <div className="text-xs text-zinc-500 mt-1 leading-relaxed">AbuseIPDB, geolocalización, puertos</div>
        </div>
        <div className="rounded-2xl bg-zinc-900/40 border border-zinc-800 p-4">
          <div className="text-xs font-bold tracking-widest text-zinc-400">APKs</div>
          <div className="text-xs text-zinc-500 mt-1 leading-relaxed">Permisos, hashes, VirusTotal</div>
        </div>
      </div>
    </div>
  );
}
