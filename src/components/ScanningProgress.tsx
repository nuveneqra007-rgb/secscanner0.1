"use client";
import { useEffect, useState } from "react";
import { ScanStep } from "@/lib/types";

const DEFAULT_STEPS: Omit<ScanStep, "status">[] = [
  { id: "normalize", label: "Normalizando indicador", detail: "Sanitizando entrada y detectando tipo (URL/IP/hash)..." },
  { id: "dns", label: "Resolviendo DNS", detail: "Consultando A, MX, TXT y PTR records..." },
  { id: "reputation", label: "Verificando reputación", detail: "Consultando AbuseIPDB, VirusTotal y blocklists..." },
  { id: "ssl", label: "Inspeccionando TLS/SSL", detail: "Validando cadena de certificados y transparencia CT..." },
  { id: "headers", label: "Analizando cabeceras HTTP", detail: "Revisando HSTS, CSP, X-Frame-Options y fingerprints..." },
  { id: "heuristic", label: "Heurística de phishing", detail: "Detectando typosquatting, homoglyphs y DGA..." },
  { id: "sandbox", label: "Correlación de inteligencia", detail: "Cruzando con feeds MISP y OTX..." },
];

export function ScanningProgress({ onComplete }: { onComplete: () => void }) {
  const [steps, setSteps] = useState<ScanStep[]>(() =>
    DEFAULT_STEPS.map((s, i) => ({ ...s, status: i === 0 ? ("running" as const) : ("pending" as const) }))
  );
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    let idx = 0;

    const interval = setInterval(() => {
      setProgress(p => Math.min(98, p + Math.random() * 12 + 4));
      setSteps(prev => {
        const next = [...prev];
        // complete current, start next
        if (next[idx]) next[idx].status = "done";
        idx++;
        if (idx < next.length) {
          next[idx].status = "running";
        } else {
          clearInterval(interval);
          setProgress(100);
          setTimeout(onComplete, 450);
        }
        return next;
      });
    }, 420 + Math.random() * 280);

    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <div className="w-full max-w-[640px] mx-auto">
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/80 backdrop-blur p-6 md:p-7">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center">
              <span className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-widest text-zinc-100">MOTOR DE ANÁLISIS</div>
              <div className="text-xs text-zinc-500 font-mono">ThreatScan Engine v2.4 • 240 reglas YARA</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs text-zinc-500 font-mono">PROGRESO</div>
            <div className="text-sm font-mono font-bold text-cyan-400">{Math.round(progress)}%</div>
          </div>
        </div>

        <div className="h-2 bg-zinc-800 rounded-full overflow-hidden mb-6 p-1">
          <div className="h-full bg-gradient-to-r from-cyan-500 to-sky-400 rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>

        <div className="space-y-3">
          {steps.map((s) => (
            <div key={s.id} className={`flex gap-3 p-3 rounded-xl border transition-all ${s.status==="running" ? "bg-zinc-800 border-zinc-700" : s.status==="done" ? "bg-zinc-900 border-zinc-800 opacity-90" : "bg-transparent border-zinc-900 opacity-60"}`}>
              <div className="mt-0.5">
                {s.status==="done" ? (
                  <div className="w-6 h-6 rounded-full bg-emerald-500 flex items-center justify-center">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3"><path d="M5 13l4 4L19 7" /></svg>
                  </div>
                ) : s.status==="running" ? (
                  <div className="w-6 h-6 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
                ) : (
                  <div className="w-6 h-6 rounded-full border border-zinc-700 bg-zinc-900" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className={`text-sm font-medium ${s.status==="running" ? "text-white" : s.status==="done" ? "text-zinc-200" : "text-zinc-500"}`}>{s.label}</div>
                <div className="text-xs text-zinc-500 font-mono truncate">{s.detail}</div>
              </div>
              <div className="text-[10px] font-mono tracking-widest px-2 py-1 rounded-full border h-fit
                data-[state=running]:bg-cyan-500/15 data-[state=running]:text-cyan-400 data-[state=running]:border-cyan-500/20
                data-[state=done]:bg-emerald-500/10 data-[state=done]:text-emerald-400 data-[state=done]:border-emerald-500/20
                data-[state=pending]:bg-zinc-900 data-[state=pending]:text-zinc-600 data-[state=pending]:border-zinc-800
                " data-state={s.status}>
                {s.status==="running" ? "EJECUTANDO" : s.status==="done" ? "COMPLETADO" : "EN ESPERA"}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 flex items-center gap-2 text-xs font-mono text-zinc-500">
          <span className="w-2 h-2 bg-amber-500 rounded-full animate-pulse" />
          No cierres esta ventana — correlacionando telemetría global
        </div>
      </div>
    </div>
  );
}
