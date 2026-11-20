"use client";
import { useEffect, useRef, useState } from "react";
import { ScanStep } from "@/lib/types";

// ── Pasos por tipo de indicador ───────────────────────────────────────────────

type IndicatorKind = "url" | "ip" | "hash" | "apk" | "file" | "domain" | "unknown";

const STEPS_BY_KIND: Record<IndicatorKind, Omit<ScanStep, "status">[]> = {
  url: [
    { id: "normalize", label: "Normalizando URL",          detail: "Decodificando, sanitizando y extrayendo componentes…" },
    { id: "dns",       label: "Resolviendo DNS",            detail: "Consultando registros A, MX, TXT, NS y PTR…" },
    { id: "whois",     label: "Consulta WHOIS",             detail: "Verificando antigüedad del dominio y datos del registrar…" },
    { id: "ssl",       label: "Inspeccionando TLS/SSL",     detail: "Validando cadena de certificados y transparencia CT…" },
    { id: "headers",   label: "Analizando cabeceras HTTP",  detail: "Revisando HSTS, CSP, X-Frame-Options y fingerprints…" },
    { id: "heuristic", label: "Heurística de phishing",     detail: "Detectando typosquatting, homoglyphs y DGA…" },
    { id: "intel",     label: "Correlación de inteligencia",detail: "Cruzando con feeds MISP, OTX y blocklists…" },
  ],
  domain: [
    { id: "normalize", label: "Normalizando dominio",       detail: "Extrayendo SLD, TLD y subdominios…" },
    { id: "dns",       label: "Resolviendo DNS",            detail: "Consultando registros A, MX, TXT, NS y PTR…" },
    { id: "whois",     label: "Consulta WHOIS",             detail: "Verificando antigüedad del dominio y datos del registrar…" },
    { id: "ssl",       label: "Inspeccionando TLS/SSL",     detail: "Validando cadena de certificados…" },
    { id: "heuristic", label: "Heurística de phishing",     detail: "Detectando typosquatting, homoglyphs y DGA…" },
    { id: "intel",     label: "Correlación de inteligencia",detail: "Cruzando con feeds MISP, OTX y blocklists…" },
  ],
  ip: [
    { id: "normalize",   label: "Validando dirección IP",     detail: "Clasificando rango (pública/privada/IPv6)…" },
    { id: "geo",         label: "Geolocalización y ASN",      detail: "Determinando país, ISP y número de sistema autónomo…" },
    { id: "reputation",  label: "Reputación global",          detail: "Consultando AbuseIPDB, Spamhaus y FireHOL…" },
    { id: "ports",       label: "Escaneando puertos",         detail: "TCP SYN scan en puertos críticos desde 3 vantage points…" },
    { id: "blocklists",  label: "Verificando blocklists",     detail: "Comparando contra listas Tor, VirusTotal y EmergingThreats…" },
    { id: "intel",       label: "Correlación de inteligencia",detail: "Cruzando con feeds MISP, OTX y campañas activas…" },
  ],
  hash: [
    { id: "normalize",   label: "Identificando hash",         detail: "Detectando algoritmo: MD5 (32), SHA-1 (40) o SHA-256 (64)…" },
    { id: "vt",          label: "Consulta VirusTotal",        detail: "Buscando en base de datos de 70+ motores antivirus…" },
    { id: "malshare",    label: "MalShare & Hybrid-Analysis", detail: "Cruzando con repositorios de muestras maliciosas…" },
    { id: "otx",         label: "AlienVault OTX",             detail: "Verificando IOC en feeds de inteligencia abierta…" },
    { id: "intel",       label: "Correlación de inteligencia",detail: "Asociando con campañas conocidas y grupos APT…" },
  ],
  apk: [
    { id: "normalize",   label: "Validando APK",              detail: "Verificando firma ZIP y magic bytes PK…" },
    { id: "manifest",    label: "Extrayendo AndroidManifest", detail: "Parseando permisos, actividades y receivers…" },
    { id: "permissions", label: "Analizando permisos",        detail: "Clasificando riesgo de cada permiso declarado…" },
    { id: "vt",          label: "Consulta VirusTotal",        detail: "Enviando hash a 70+ motores antivirus…" },
    { id: "yara",        label: "Reglas YARA",                detail: "Aplicando 240 firmas de familias de malware Android…" },
    { id: "intel",       label: "Correlación de inteligencia",detail: "Asociando con familias Anubis, Cerberus, SpyNote…" },
  ],
  file: [
    { id: "normalize",   label: "Identificando archivo",      detail: "Detectando tipo por magic bytes y extensión…" },
    { id: "hashes",      label: "Calculando hashes",          detail: "Generando MD5, SHA-1, SHA-256 y ssdeep…" },
    { id: "entropy",     label: "Análisis de entropía",       detail: "Detectando empaquetado, cifrado u ofuscación…" },
    { id: "vt",          label: "Consulta VirusTotal",        detail: "Buscando en 70+ motores antivirus…" },
    { id: "yara",        label: "Reglas YARA",                detail: "Aplicando 240 firmas de familias de malware…" },
    { id: "intel",       label: "Correlación de inteligencia",detail: "Cruzando con feeds MISP, OTX y campañas activas…" },
  ],
  unknown: [
    { id: "normalize",   label: "Normalizando indicador",     detail: "Sanitizando entrada y detectando tipo…" },
    { id: "heuristic",   label: "Análisis heurístico",        detail: "Aplicando reglas de detección generales…" },
    { id: "intel",       label: "Correlación de inteligencia",detail: "Cruzando con feeds de inteligencia…" },
  ],
};

// ── Componente ────────────────────────────────────────────────────────────────

export function ScanningProgress({
  onComplete,
  indicatorKind = "unknown",
}: {
  onComplete: () => void;
  indicatorKind?: IndicatorKind;
}) {
  const kind   = indicatorKind in STEPS_BY_KIND ? indicatorKind : "unknown";
  const stepDefs = STEPS_BY_KIND[kind];

  const [steps,    setSteps]    = useState<ScanStep[]>(() =>
    stepDefs.map((s, i) => ({ ...s, status: i === 0 ? "running" as const : "pending" as const }))
  );
  const [progress, setProgress] = useState(0);

  // Fix #2: usar ref para onComplete para evitar que el cambio de referencia reinicie el efecto
  const onCompleteRef = useRef(onComplete);
  useEffect(() => { onCompleteRef.current = onComplete; }, [onComplete]);

  useEffect(() => {
    let idx = 0;
    const total = stepDefs.length;

    const interval = setInterval(() => {
      setProgress(() => Math.min(98, Math.round(((idx + 1) / total) * 95)));

      setSteps((prev) => {
        const next = [...prev];
        if (next[idx]) next[idx] = { ...next[idx], status: "done" };
        idx++;
        if (idx < next.length) {
          next[idx] = { ...next[idx], status: "running" };
        } else {
          clearInterval(interval);
          setProgress(100);
          setTimeout(() => onCompleteRef.current(), 400);
        }
        return next;
      });
    }, 380 + Math.random() * 240);

    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // sin dependencias — el efecto corre una sola vez por montaje

  const kindLabel: Record<IndicatorKind, string> = {
    url: "URL", domain: "Dominio", ip: "IP",
    hash: "Hash", apk: "APK", file: "Archivo", unknown: "Indicador",
  };

  return (
    <div className="w-full max-w-[600px] mx-auto">
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/80 backdrop-blur p-6">
        {/* Cabecera */}
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center shrink-0">
              <span className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-widest text-zinc-100">
                Analizando {kindLabel[kind]}
              </div>
              <div className="text-[11px] text-zinc-500 font-mono mt-0.5">
                ThreatScan Engine v2.4 · {stepDefs.length} módulos
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-zinc-600 font-mono">PROGRESO</div>
            <div className="text-base font-black font-mono text-cyan-400">{Math.round(progress)}%</div>
          </div>
        </div>

        {/* Barra de progreso */}
        <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden mb-5">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 to-sky-400 rounded-full transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Pasos */}
        <div className="space-y-2">
          {steps.map((s) => (
            <div
              key={s.id}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl border transition-all duration-300
                ${s.status === "running"  ? "bg-zinc-800 border-zinc-700"
                : s.status === "done"    ? "bg-zinc-900/60 border-zinc-800/60 opacity-80"
                : "bg-transparent border-transparent opacity-40"}`}
            >
              {/* Icono de estado */}
              <div className="shrink-0">
                {s.status === "done" ? (
                  <div className="w-5 h-5 rounded-full bg-emerald-500 flex items-center justify-center">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3">
                      <path d="M5 13l4 4L19 7"/>
                    </svg>
                  </div>
                ) : s.status === "running" ? (
                  <div className="w-5 h-5 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
                ) : (
                  <div className="w-5 h-5 rounded-full border border-zinc-700" />
                )}
              </div>

              {/* Texto */}
              <div className="flex-1 min-w-0">
                <div className={`text-sm font-medium leading-none mb-0.5
                  ${s.status === "running" ? "text-white" : s.status === "done" ? "text-zinc-300" : "text-zinc-600"}`}>
                  {s.label}
                </div>
                {s.status !== "pending" && (
                  <div className="text-[11px] text-zinc-600 font-mono truncate">{s.detail}</div>
                )}
              </div>

              {/* Badge */}
              {s.status !== "pending" && (
                <span className={`text-[10px] font-bold tracking-widest px-2 py-0.5 rounded-full border shrink-0
                  ${s.status === "running"
                    ? "bg-cyan-500/15 text-cyan-400 border-cyan-500/20"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`}>
                  {s.status === "running" ? "EN CURSO" : "OK"}
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-5 flex items-center gap-2 text-[11px] font-mono text-zinc-600">
          <span className="w-1.5 h-1.5 bg-amber-500 rounded-full animate-pulse shrink-0" />
          Análisis heurístico local · sin enviar datos a servidores externos
        </div>
      </div>
    </div>
  );
}
