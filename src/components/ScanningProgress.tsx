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
  const kind = indicatorKind in STEPS_BY_KIND ? indicatorKind : "unknown";
  const stepDefs = STEPS_BY_KIND[kind];

  const [steps, setSteps] = useState<ScanStep[]>(() =>
    stepDefs.map((s, i) => ({ ...s, status: i === 0 ? ("running" as const) : ("pending" as const) }))
  );
  const [progress, setProgress] = useState(0);

  const onCompleteRef = useRef(onComplete);
  useEffect(() => {
    onCompleteRef.current = onComplete;
  }, [onComplete]);

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
    }, 360 + Math.random() * 200);

    return () => clearInterval(interval);
  }, [stepDefs.length]);

  const kindLabel: Record<IndicatorKind, string> = {
    url: "URL",
    domain: "Dominio",
    ip: "IP",
    hash: "Hash",
    apk: "APK",
    file: "Archivo",
    unknown: "Indicador",
  };

  return (
    <div className="w-full max-w-[620px] mx-auto animate-glitch-in">
      <div className="rounded-2xl border border-[#333333] bg-[#121212]/90 backdrop-blur p-6 relative overflow-hidden shadow-2xl">
        {/* Subtle scanline line */}
        <div
          className="absolute left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-white/20 to-transparent pointer-events-none"
          style={{ animation: "scanSweep 2.5s ease-in-out infinite" }}
        />

        {/* Cabecera */}
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#1A1A1A] border border-[#333333] flex items-center justify-center shrink-0">
              <span className="w-2.5 h-2.5 bg-white rounded-full animate-ping" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-widest text-white uppercase">
                Analizando {kindLabel[kind]}
              </div>
              <div className="text-[11px] text-[#A3A3A3] font-mono mt-0.5">
                SecScanner Engine v0.1 · {stepDefs.length} módulos
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-[#666666] font-mono tracking-wider">PROGRESO</div>
            <div className="text-lg font-black font-mono text-white">{Math.round(progress)}%</div>
          </div>
        </div>

        {/* Barra de progreso */}
        <div className="h-1.5 bg-[#1A1A1A] rounded-full overflow-hidden mb-5 border border-[#333333]/40">
          <div
            className="h-full bg-gradient-to-r from-[#888888] via-white to-[#E0E0E0] rounded-full transition-all duration-300 shadow-[0_0_8px_rgba(255,255,255,0.4)]"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Pasos */}
        <div className="space-y-2">
          {steps.map((s) => (
            <div
              key={s.id}
              className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl border transition-all duration-300 ${
                s.status === "running"
                  ? "bg-[#1A1A1A] border-white/30 shadow-[0_0_15px_rgba(255,255,255,0.04)]"
                  : s.status === "done"
                  ? "bg-[#0E0E0E] border-[#222222] opacity-80"
                  : "bg-transparent border-transparent opacity-30"
              }`}
            >
              {/* Icono de estado */}
              <div className="shrink-0">
                {s.status === "done" ? (
                  <div className="w-5 h-5 rounded-full bg-[#E0E0E0] text-black flex items-center justify-center">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                ) : s.status === "running" ? (
                  <div className="w-5 h-5 rounded-full border-2 border-white border-t-transparent animate-spin" />
                ) : (
                  <div className="w-5 h-5 rounded-full border border-[#333333]" />
                )}
              </div>

              {/* Texto */}
              <div className="flex-1 min-w-0">
                <div
                  className={`text-sm font-medium leading-none mb-0.5 ${
                    s.status === "running" ? "text-white" : s.status === "done" ? "text-[#D4D4D4]" : "text-[#666666]"
                  }`}
                >
                  {s.label}
                </div>
                {s.status !== "pending" && (
                  <div className="text-[11px] text-[#A3A3A3] font-mono truncate">{s.detail}</div>
                )}
              </div>

              {/* Badge */}
              {s.status !== "pending" && (
                <span
                  className={`text-[10px] font-bold tracking-widest px-2.5 py-0.5 rounded-full border shrink-0 ${
                    s.status === "running"
                      ? "bg-white/10 text-white border-white/20 animate-pulse"
                      : "bg-[#E0E0E0]/10 text-[#E0E0E0] border-[#E0E0E0]/20"
                  }`}
                >
                  {s.status === "running" ? "EN CURSO" : "OK"}
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-5 pt-4 border-t border-[#222222] flex items-center gap-2 text-[11px] font-mono text-[#666666]">
          <span className="w-1.5 h-1.5 bg-[#E0E0E0] rounded-full animate-pulse shrink-0" />
          Análisis heurístico local · sin enviar datos a servidores externos
        </div>
      </div>
    </div>
  );
}
