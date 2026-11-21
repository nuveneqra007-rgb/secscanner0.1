"use client";
import { useState } from "react";
import { ScanResult, Severity } from "@/lib/types";
import { formatDate, severityLabel } from "@/lib/utils";
import { RiskGauge, RiskBar } from "./RiskGauge";

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const severityStyle: Record<Severity, { badge: string; icon: string; row: string; dot: string }> = {
  critical: {
    badge: "bg-[#FF3333] text-white border-[#FF3333]",
    icon:  "bg-[#FF3333] border-[#FF3333] text-white",
    row:   "border-l-[#FF3333]",
    dot:   "bg-[#FF3333]",
  },
  high: {
    badge: "bg-[#FF3333]/80 text-white border-[#FF3333]",
    icon:  "bg-[#FF3333]/90 border-[#FF3333] text-white",
    row:   "border-l-[#FF3333]",
    dot:   "bg-[#FF3333]",
  },
  medium: {
    badge: "bg-[#A3A3A3] text-black border-[#A3A3A3]",
    icon:  "bg-[#A3A3A3] border-[#A3A3A3] text-black",
    row:   "border-l-[#A3A3A3]",
    dot:   "bg-[#A3A3A3]",
  },
  low: {
    badge: "bg-[#666666] text-white border-[#666666]",
    icon:  "bg-[#666666] border-[#666666] text-white",
    row:   "border-l-[#666666]",
    dot:   "bg-[#666666]",
  },
  info: {
    badge: "bg-[#222222] text-[#888888] border-[#333333]",
    icon:  "bg-[#1A1A1A] border-[#333333] text-[#888888]",
    row:   "border-l-[#333333]",
    dot:   "bg-[#444444]",
  },
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "!",
  high:     "▲",
  medium:   "◐",
  low:      "●",
  info:     "i",
};

type EvidenceTab = "whois" | "dns" | "ssl" | "headers" | "redirects" | "geo" | "reputation" | "ports" | "file" | "iocs";

// ── Badges de verificación y procedencia de datos ─────────────────────────────

function SimulatedBadge() {
  return (
    <span
      title="Estos datos son generados heurísticamente con fines de demostración. No representan información real del indicador."
      className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#1A1A1A] border border-[#333333] text-[#A3A3A3] cursor-help"
    >
      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      Simulado
    </span>
  );
}

function VerificationBadge({ result }: { result: ScanResult }) {
  const isLive = result.isLive || result.dataSource === "live";

  if (!isLive) {
    return <SimulatedBadge />;
  }

  return (
    <span
      title="Análisis ejecutado en vivo con verificación criptográfica, consultas DNS/TLS y feeds de ciberinteligencia en tiempo real."
      className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold tracking-wider px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/50 text-emerald-400 cursor-help shadow-sm shadow-emerald-950/50"
    >
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
      ✓ Verificado en Vivo
    </span>
  );
}

function SourceTabBadge({ result, tab }: { result: ScanResult; tab: EvidenceTab }) {
  if (!result.isLive && result.dataSource !== "live") {
    return <SimulatedBadge />;
  }

  const sources = result.sources || {};
  let isLive = true;

  if (tab === "whois") isLive = sources.rdap === "live";
  else if (tab === "dns") isLive = sources.dns === "live";
  else if (tab === "ssl") isLive = sources.tls === "live";
  else if (tab === "headers" || tab === "redirects") isLive = sources.headers === "live";
  else if (tab === "geo") isLive = sources.geo === "live";
  else if (tab === "reputation") isLive = sources.virustotal === "live" || sources.abuseipdb === "live" || sources.threatintel === "live";
  else if (tab === "ports") isLive = sources.shodan === "live";
  else if (tab === "file") isLive = sources.static === "live";
  else if (tab === "iocs") isLive = true;

  if (isLive) {
    return (
      <span
        title="Datos consultados y validados en tiempo real desde APIs y servicios autoritativos."
        className="inline-flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded-full bg-emerald-950/70 border border-emerald-500/40 text-emerald-400 cursor-help shadow-sm"
      >
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
        ✓ En Vivo
      </span>
    );
  }

  return (
    <span
      title="Servicio no disponible o sin registros para este indicador."
      className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#1A1A1A] border border-[#333333] text-[#737373] cursor-help"
    >
      ⚠ No disponible
    </span>
  );
}

function SeverityBadge({ s }: { s: Severity }) {
  return (
    <span className={`text-[10px] font-bold tracking-widest px-2.5 py-0.5 rounded-full border ${severityStyle[s].badge}`}>
      {severityLabel(s)}
    </span>
  );
}

function KV({ label, value, accent }: { label: string; value?: string | null; accent?: string }) {
  if (!value) return null;
  return (
    <div className="flex justify-between gap-3 text-xs font-mono py-1.5 border-b border-[#222222] last:border-0">
      <span className="text-[#666666] shrink-0">{label}</span>
      <span className={`text-right break-all ${accent ?? "text-[#D4D4D4]"}`}>{value}</span>
    </div>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-[#0A0A0A] border border-[#333333] p-4 space-y-0">
      {children}
    </div>
  );
}

// ── FindingsAccordion ─────────────────────────────────────────────────────────

function FindingsAccordion({ result }: { result: ScanResult }) {
  const [openSections, setOpenSections] = useState<Set<Severity>>(
    new Set(["critical", "high"] as Severity[])
  );
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const toggle = (sev: Severity) => {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) { next.delete(sev); } else { next.add(sev); }
      return next;
    });
  };

  const toggleFinding = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) { next.delete(id); } else { next.add(id); }
      return next;
    });
  };

  const grouped = SEVERITY_ORDER.reduce<Record<Severity, typeof result.findings[0][]>>(
    (acc, sev) => {
      acc[sev] = result.findings.filter((f) => f.severity === sev);
      return acc;
    },
    { critical: [], high: [], medium: [], low: [], info: [] }
  );

  return (
    <div className="space-y-2">
      {SEVERITY_ORDER.map((sev) => {
        const items = grouped[sev];
        if (items.length === 0) return null;
        const isOpen = openSections.has(sev);
        const st = severityStyle[sev];

        return (
          <div key={sev} className="rounded-xl border border-[#333333] overflow-hidden">
            {/* Cabecera de sección */}
            <button
              onClick={() => toggle(sev)}
              className="w-full flex items-center justify-between px-5 py-3.5 bg-[#121212] hover:bg-[#1A1A1A] transition"
            >
              <div className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${st.dot}`} />
                <span className="text-sm font-bold text-white uppercase">{severityLabel(sev)}</span>
                <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${st.badge}`}>
                  {items.length}
                </span>
              </div>
              <svg
                width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="#666666" strokeWidth="2"
                className={`transition-transform ${isOpen ? "rotate-180" : ""}`}
              >
                <path d="M6 9l6 6 6-6" />
              </svg>
            </button>

            {/* Findings dentro */}
            {isOpen && (
              <div className="divide-y divide-[#222222]">
                {items.map((f) => {
                  const isExpanded = expandedIds.has(f.id);
                  return (
                    <div key={f.id} className={`border-l-2 ${st.row} bg-[#0A0A0A]`}>
                      {/* Fila del finding */}
                      <button
                        onClick={() => toggleFinding(f.id)}
                        className="w-full text-left flex items-start gap-4 px-5 py-4 hover:bg-[#121212] transition"
                      >
                        <div className={`mt-0.5 w-7 h-7 rounded-lg flex items-center justify-center border text-[11px] font-black shrink-0 ${st.icon}`}>
                          {SEVERITY_ICONS[f.severity]}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <SeverityBadge s={f.severity} />
                            <span className="text-sm font-semibold text-white">{f.title}</span>
                            {f.mitre && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-white/10 text-[#E0E0E0] border border-white/20">
                                {f.mitre}
                              </span>
                            )}
                            {f.cwe && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#1A1A1A] text-[#888888] border border-[#333333]">
                                {f.cwe}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-[#A3A3A3] leading-relaxed line-clamp-2">{f.description}</p>
                        </div>
                        <svg
                          width="14" height="14" viewBox="0 0 24 24" fill="none"
                          stroke="#666666" strokeWidth="2"
                          className={`mt-1 shrink-0 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                        >
                          <path d="M6 9l6 6 6-6" />
                        </svg>
                      </button>

                      {/* Evidencia expandida */}
                      {isExpanded && f.evidence && (
                        <div className="px-5 pb-4">
                          <div className="rounded-xl bg-[#121212] border border-[#333333] p-4">
                            <div className="text-[10px] tracking-widest font-bold text-[#666666] mb-2 uppercase">EVIDENCIA TÉCNICA</div>
                            <p className="text-xs font-mono text-[#E0E0E0] break-all leading-relaxed">{f.evidence}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── EvidenceTabs ──────────────────────────────────────────────────────────────

function EvidenceTabs({ result }: { result: ScanResult }) {
  const ev = result.evidence;

  // Construir tabs disponibles
  const availableTabs: { id: EvidenceTab; label: string }[] = [];
  if (ev.whois || ev.dns)        availableTabs.push({ id: "whois",     label: "WHOIS & DNS" });
  if (ev.ssl)                    availableTabs.push({ id: "ssl",       label: "TLS / SSL" });
  if (ev.httpHeaders)            availableTabs.push({ id: "headers",   label: "Cabeceras" });
  if ((ev.redirectChain?.length ?? 0) > 1)
                                 availableTabs.push({ id: "redirects", label: "Redirecciones" });
  if (ev.geolocation)            availableTabs.push({ id: "geo",       label: "Geolocalización" });
  if (ev.reputation)             availableTabs.push({ id: "reputation",label: "Reputación" });
  if ((ev.ports?.length ?? 0) > 0)
                                 availableTabs.push({ id: "ports",     label: "Puertos" });
  if (ev.fileInfo)               availableTabs.push({ id: "file",      label: "Archivo" });
  if ((ev.iocs?.length ?? 0) > 0)
                                 availableTabs.push({ id: "iocs",      label: "IoCs" });

  const [active, setActive] = useState<EvidenceTab>(availableTabs[0]?.id ?? "whois");

  if (availableTabs.length === 0) return null;

  return (
    <div className="rounded-2xl border border-[#333333] bg-[#121212]/80 overflow-hidden shadow-xl">
      {/* Tab bar */}
      <div className="flex items-center border-b border-[#333333] overflow-x-auto bg-[#0E0E0E]">
        <div className="flex">
          {availableTabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setActive(t.id)}
              className={`px-4 py-3 text-[11px] font-bold tracking-wider whitespace-nowrap transition-colors ${
                active === t.id
                  ? "text-white border-b-2 border-white -mb-px bg-[#1A1A1A]"
                  : "text-[#666666] hover:text-[#A3A3A3]"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="ml-auto px-4 shrink-0">
          <SourceTabBadge result={result} tab={active} />
        </div>
      </div>

      {/* Contenido del tab activo */}
      <div className="p-5">

        {/* WHOIS & DNS */}
        {active === "whois" && (
          <div className="grid sm:grid-cols-2 gap-4">
            {ev.whois && (
              <div>
                <div className="text-xs font-semibold text-[#A3A3A3] mb-2 uppercase tracking-wider">WHOIS</div>
                <Panel>
                  <KV label="Registrar"  value={ev.whois.registrar} />
                  <KV label="Creado"     value={ev.whois.created ? `${ev.whois.created.slice(0,10)} (${ev.whois.ageDays}d)` : null} />
                  <KV label="Expira"     value={ev.whois.expires?.slice(0,10)} />
                  <KV label="NS"         value={ev.dns?.ns?.join(", ")} />
                </Panel>
              </div>
            )}
            {ev.dns && (
              <div>
                <div className="text-xs font-semibold text-[#A3A3A3] mb-2 uppercase tracking-wider">DNS</div>
                <Panel>
                  <KV label="A"   value={ev.dns.a?.join(", ")} accent="text-white font-bold" />
                  <KV label="MX"  value={ev.dns.mx?.join(", ")} />
                  <KV label="TXT" value={ev.dns.txt?.join(" | ")} />
                  <KV label="PTR" value={ev.reverseDns} />
                </Panel>
              </div>
            )}
          </div>
        )}

        {/* TLS / SSL */}
        {active === "ssl" && ev.ssl && (
          <Panel>
            <KV label="Emisor"      value={ev.ssl.issuer} />
            <KV label="Sujeto"      value={ev.ssl.subject} />
            <KV label="Válido hasta"
               value={ev.ssl.validTo ? `${ev.ssl.validTo.slice(0,10)} (${ev.ssl.daysUntilExpiry}d)` : null}
               accent={ev.ssl.expired ? "text-[#FF3333] font-bold" : "text-[#E0E0E0]"} />
            <KV label="SANs"        value={ev.ssl.sans?.join(", ")} />
            {ev.ssl.expired && (
              <div className="mt-3 rounded-lg bg-[#FF3333]/10 border border-[#FF3333]/30 px-3 py-2 text-xs text-[#FF3333] font-mono">
                ⚠ Certificado expirado
              </div>
            )}
          </Panel>
        )}

        {/* Cabeceras HTTP */}
        {active === "headers" && ev.httpHeaders && (
          <div className="rounded-xl bg-[#0A0A0A] border border-[#333333] p-4 max-h-64 overflow-auto">
            <div className="space-y-1.5 text-[11px] font-mono">
              {Object.entries(ev.httpHeaders)
                .filter(([, v]) => v)
                .map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-[#666666] shrink-0">{k}:</span>
                    <span className="text-[#D4D4D4] break-all">{v}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Redirecciones */}
        {active === "redirects" && ev.redirectChain && (
          <div className="space-y-2">
            {ev.redirectChain.map((r, i) => (
              <div key={i} className="flex gap-3 items-start rounded-xl bg-[#0A0A0A] border border-[#333333] px-4 py-3">
                <span className={`shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full border h-fit ${
                  r.status === 200
                    ? "bg-[#E0E0E0]/15 text-[#E0E0E0] border-[#E0E0E0]/30"
                    : "bg-[#A3A3A3]/15 text-[#A3A3A3] border-[#A3A3A3]/30"
                }`}>
                  {r.status}
                </span>
                <span className="text-xs font-mono text-[#D4D4D4] break-all">{r.url}</span>
              </div>
            ))}
          </div>
        )}

        {/* Geolocalización */}
        {active === "geo" && ev.geolocation && (
          <div className="space-y-4">
            <div className="flex gap-4 items-center">
              <div className="w-12 h-12 rounded-xl bg-[#1A1A1A] border border-[#333333] flex items-center justify-center text-xl shrink-0">
                🌐
              </div>
              <div>
                <div className="text-sm font-semibold text-white">
                  {ev.geolocation.city}, {ev.geolocation.country}
                </div>
                <div className="text-xs font-mono text-[#666666] mt-0.5">
                  {ev.geolocation.lat.toFixed(4)}, {ev.geolocation.lon.toFixed(4)}
                </div>
              </div>
            </div>
            <Panel>
              <KV label="ASN"           value={ev.geolocation.asn} />
              <KV label="ISP"           value={ev.geolocation.isp} />
              <KV label="Organización"  value={ev.geolocation.org} />
              <KV label="Región"        value={ev.geolocation.region} />
            </Panel>
          </div>
        )}

        {/* Reputación */}
        {active === "reputation" && ev.reputation && (
          <div className="space-y-4">
            {/* Score */}
            <div className="flex items-center gap-4">
              <div className={`w-16 h-16 rounded-2xl flex flex-col items-center justify-center border shrink-0 ${
                ev.reputation.abuseScore > 70
                  ? "bg-[#FF3333]/10 border-[#FF3333]/30 text-[#FF3333]"
                  : ev.reputation.abuseScore > 30
                  ? "bg-[#A3A3A3]/10 border-[#A3A3A3]/30 text-[#A3A3A3]"
                  : "bg-[#E0E0E0]/10 border-[#E0E0E0]/30 text-[#E0E0E0]"
              }`}>
                <span className="text-xl font-black">{ev.reputation.abuseScore}</span>
                <span className="text-[9px] tracking-widest uppercase">ABUSE</span>
              </div>
              <div className="text-xs font-mono text-[#888888] space-y-1">
                <div><span className="text-white font-bold">{ev.reputation.totalReports}</span> reportes (90d)</div>
                {ev.reputation.lastReported && (
                  <div>Último: {ev.reputation.lastReported.slice(0,10)}</div>
                )}
              </div>
            </div>
            {/* Blacklists */}
            <div className="space-y-2">
              {ev.reputation.blacklists.map((b) => (
                <div key={b.name} className="flex items-center justify-between rounded-xl bg-[#0A0A0A] border border-[#333333] px-4 py-2.5">
                  <span className="text-xs font-medium text-white">{b.name}</span>
                  <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border ${
                    b.listed
                      ? "bg-[#FF3333] text-white border-[#FF3333]"
                      : "bg-[#E0E0E0]/15 text-[#E0E0E0] border-[#E0E0E0]/30"
                  }`}>
                    {b.listed ? "LISTADO" : "LIMPIO"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Puertos */}
        {active === "ports" && ev.ports && (
          <div className="space-y-2">
            {ev.ports.map((p) => (
              <div key={p.port} className="flex items-center justify-between rounded-xl bg-[#0A0A0A] border border-[#333333] px-4 py-3">
                <div>
                  <span className="text-sm font-mono font-bold text-white">{p.port}</span>
                  <span className="text-[#666666] font-mono text-sm">/tcp</span>
                  <span className="text-xs text-[#888888] ml-3">{p.service}</span>
                </div>
                <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border ${
                  p.risk === "critical" || p.risk === "high"
                    ? "bg-[#FF3333] text-white border-[#FF3333]"
                    : p.risk === "medium"
                    ? "bg-[#A3A3A3] text-black border-[#A3A3A3]"
                    : "bg-[#E0E0E0] text-black border-[#E0E0E0]"
                }`}>
                  {p.risk.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Archivo / Hash */}
        {active === "file" && ev.fileInfo && (
          <div className="space-y-4">
            <Panel>
              <KV label="Nombre"  value={ev.fileInfo.name} />
              <KV label="Tamaño"  value={ev.fileInfo.size} />
              <KV label="Tipo"    value={ev.fileInfo.type} />
              {ev.fileInfo.entropy != null && (
                <KV label="Entropía" value={`${ev.fileInfo.entropy.toFixed(2)} / 8.0`} accent="text-[#E0E0E0]" />
              )}
              <KV label="MD5"    value={ev.fileInfo.md5}    accent="text-white font-mono" />
              <KV label="SHA1"   value={ev.fileInfo.sha1}   accent="text-white font-mono" />
              <KV label="SHA256" value={ev.fileInfo.sha256} accent="text-white font-mono" />
              {ev.ssdeep && <KV label="ssdeep" value={ev.ssdeep} accent="text-[#888888]" />}
            </Panel>
            {ev.vtDetections && ev.vtDetections.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-[#A3A3A3] mb-2 uppercase tracking-wider">VirusTotal</div>
                <div className="rounded-xl bg-[#0A0A0A] border border-[#333333] divide-y divide-[#222222]">
                  {ev.vtDetections.map((v, i) => (
                    <div key={i} className="flex justify-between px-4 py-2 text-xs font-mono">
                      <span className="text-[#888888]">{v.engine}</span>
                      <span className={v.result === "Clean" ? "text-[#E0E0E0]" : "text-[#FF3333] font-bold"}>{v.result}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {ev.permissions && ev.permissions.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-[#A3A3A3] mb-2 uppercase tracking-wider">Permisos APK</div>
                <div className="space-y-2 max-h-64 overflow-auto pr-1">
                  {ev.permissions.map((p) => (
                    <div key={p.name} className="rounded-xl bg-[#0A0A0A] border border-[#333333] p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-2 h-2 rounded-full ${
                          p.severity === "critical" || p.severity === "high"
                            ? "bg-[#FF3333]"
                            : p.severity === "medium"
                            ? "bg-[#A3A3A3]"
                            : "bg-[#E0E0E0]"
                        }`} />
                        <span className="text-xs font-mono font-semibold text-white truncate">{p.name}</span>
                      </div>
                      <p className="text-xs text-[#888888] leading-relaxed">{p.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* IoCs */}
        {active === "iocs" && ev.iocs && (
          <div className="rounded-xl bg-[#0A0A0A] border border-[#333333] overflow-hidden">
            <table className="w-full text-xs font-mono">
              <thead className="bg-[#121212] text-[#666666]">
                <tr>
                  <th className="text-left px-4 py-2.5 font-medium uppercase">Tipo</th>
                  <th className="text-left px-4 py-2.5 font-medium uppercase">Valor</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222222]">
                {ev.iocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-[#1A1A1A]/40">
                    <td className="px-4 py-2.5 text-[#666666] whitespace-nowrap">{ioc.type}</td>
                    <td className="px-4 py-2.5 text-white break-all font-mono">{ioc.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      </div>
    </div>
  );
}

// ── ThreatReport ──────────────────────────────────────────────────────────────

export function ThreatReport({
  result,
  onNewScan,
}: {
  result: ScanResult;
  onNewScan?: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const counts = result.findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const verdictStyle =
    result.verdict === "malicious"
      ? { ring: "border-[#FF3333]/40", bg: "from-[#FF3333]/10", badge: "bg-[#FF3333] text-white border-[#FF3333]", label: "● MALICIOSO" }
      : result.verdict === "suspicious"
      ? { ring: "border-[#A3A3A3]/40", bg: "from-[#A3A3A3]/10", badge: "bg-[#A3A3A3] text-black border-[#A3A3A3]", label: "● SOSPECHOSO" }
      : { ring: "border-[#E0E0E0]/30", bg: "from-[#E0E0E0]/5", badge: "bg-[#E0E0E0] text-black border-[#E0E0E0]", label: "● LIMPIO" };

  const gradeColor =
    result.riskScore >= 75
      ? "text-[#FF3333] border-[#FF3333]/30 bg-[#FF3333]/10"
      : result.riskScore >= 40
      ? "text-[#A3A3A3] border-[#A3A3A3]/30 bg-[#A3A3A3]/10"
      : "text-[#E0E0E0] border-[#E0E0E0]/30 bg-[#E0E0E0]/10";

  const getExportData = () => ({
    ...result,
    _metadata: {
      engine: "SecScanner 0.1 Threat Intelligence Engine",
      dataSource: result.isLive ? "live_verified" : "simulated_heuristic",
      exportedAt: new Date().toISOString(),
      verifiedSources: result.sources || {},
    },
  });

  const copyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(getExportData(), null, 2));
  };

  const downloadJSON = () => {
    const data = getExportData();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `secscanner_${result.type}_${result.id.slice(0, 16)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const shareUrl = () => {
    const url = `${window.location.origin}/scan/${result.id}`;
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="w-full space-y-5 animate-glitch-in">

      {/* ── Resumen ejecutivo ── */}
      <div className={`rounded-2xl border px-4 sm:px-5 py-4 flex flex-col sm:flex-row sm:items-center gap-4 max-w-full box-border overflow-hidden ${
        result.verdict === "malicious"
          ? "border-[#FF3333]/40 bg-[#FF3333]/5"
          : result.verdict === "suspicious"
          ? "border-[#A3A3A3]/40 bg-[#A3A3A3]/5"
          : "border-[#E0E0E0]/30 bg-[#E0E0E0]/5"
      }`}>
        {/* Score grande con tipografia fluida clamp */}
        <div className={`text-[clamp(2.25rem,6vw,3.5rem)] font-black tabular-nums shrink-0 leading-none ${
          result.riskScore >= 75 ? "text-[#FF3333]" : result.riskScore >= 40 ? "text-[#A3A3A3]" : "text-[#E0E0E0]"
        }`}>
          {result.riskScore}
          <span className="text-[clamp(0.95rem,2.2vw,1.25rem)] font-normal text-[#666666] ml-1">/100</span>
        </div>
        {/* Separador vertical */}
        <div className="hidden sm:block w-px h-12 bg-[#333333] shrink-0" />
        {/* Texto */}
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <span className={`text-xs font-black tracking-widest px-3 py-1 rounded-full border ${
              result.verdict === "malicious"
                ? "bg-[#FF3333] text-white border-[#FF3333]"
                : result.verdict === "suspicious"
                ? "bg-[#A3A3A3] text-black border-[#A3A3A3]"
                : "bg-[#E0E0E0] text-black border-[#E0E0E0]"
            }`}>
              {result.verdict === "malicious" ? "● MALICIOSO" : result.verdict === "suspicious" ? "● SOSPECHOSO" : "● LIMPIO"}
            </span>
            <span className="text-xs font-mono text-[#A3A3A3]">
              Grado {result.grade} · {result.type.toUpperCase()} · Confianza {result.confidence}
            </span>
            <VerificationBadge result={result} />
          </div>
          <p className="text-xs sm:text-sm text-[#D4D4D4] leading-relaxed line-clamp-2">{result.summary}</p>
        </div>
      </div>

      {/* ── Barra superior ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 max-w-full">
        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-[10px] sm:text-[11px] font-mono text-[#666666]">
          <span className="px-2.5 py-1 rounded-full bg-[#121212] border border-[#333333]">
            ID: {result.id.slice(0, 16).toUpperCase()}
          </span>
          <span className="px-2.5 py-1 rounded-full bg-[#121212] border border-[#333333]">
            {formatDate(result.timestamp)}
          </span>
          <span className="px-2.5 py-1 rounded-full bg-[#121212] border border-[#333333]">
            {result.scanDurationMs} ms
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="px-3.5 sm:px-4 py-2 rounded-lg bg-white text-black text-xs sm:text-sm font-bold hover:bg-[#E0E0E0] transition neon-hover border border-transparent whitespace-nowrap"
            >
              Nuevo análisis
            </button>
          )}
          <button
            onClick={copyJSON}
            className="px-3 sm:px-4 py-2 rounded-lg bg-[#121212] border border-[#333333] text-xs sm:text-sm font-medium text-[#A3A3A3] hover:text-white hover:bg-[#1A1A1A] transition whitespace-nowrap"
          >
            Copiar JSON
          </button>
          <button
            onClick={downloadJSON}
            className="px-3 sm:px-4 py-2 rounded-lg bg-[#121212] border border-[#333333] text-xs sm:text-sm font-medium text-[#A3A3A3] hover:text-white hover:bg-[#1A1A1A] transition flex items-center gap-1.5 whitespace-nowrap"
            title="Descargar reporte forense estructurado en formato JSON"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Exportar JSON
          </button>
          <button
            onClick={shareUrl}
            className="px-3 sm:px-4 py-2 rounded-lg bg-[#121212] border border-[#333333] text-xs sm:text-sm font-medium text-[#A3A3A3] hover:text-white hover:bg-[#1A1A1A] transition flex items-center gap-1.5 whitespace-nowrap"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/>
            </svg>
            {copied ? "¡Copiado!" : "Compartir"}
          </button>
          <button
            onClick={() => window.print()}
            className="hidden md:inline-flex px-3 sm:px-4 py-2 rounded-lg bg-[#121212] border border-[#333333] text-xs sm:text-sm font-medium text-[#A3A3A3] hover:text-white hover:bg-[#1A1A1A] transition whitespace-nowrap"
          >
            Imprimir
          </button>
        </div>
      </div>

      {/* ── Hero card ── */}
      <div className={`rounded-2xl border overflow-hidden ${verdictStyle.ring} bg-gradient-to-br ${verdictStyle.bg} via-[#121212] to-[#0A0A0A] shadow-2xl max-w-full box-border`}>
        <div className="p-4 sm:p-6 lg:p-7">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_200px] gap-6 items-start">
            <div className="min-w-0 max-w-full">
              {/* Badges de estado */}
              <div className="flex flex-wrap items-center gap-2 mb-3">
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${verdictStyle.badge}`}>
                  {verdictStyle.label}
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-mono bg-[#1A1A1A] border border-[#333333] text-white">
                  {result.type.toUpperCase()} · {result.confidence}
                </span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${gradeColor}`}>
                  GRADO {result.grade}
                </span>
              </div>

              {/* Indicador con tipografia fluida */}
              <h1 className="text-[clamp(1.1rem,3vw,1.35rem)] font-semibold text-white break-all leading-snug font-mono">
                {result.normalizedInput}
              </h1>
              <p className="mt-2 text-xs sm:text-sm leading-relaxed text-[#A3A3A3] max-w-[640px]">
                {result.summary}
              </p>

              {/* Barra de riesgo */}
              <div className="mt-5">
                <RiskBar score={result.riskScore} />
                <div className="flex justify-between mt-1.5 text-[10px] font-mono tracking-widest text-[#666666]">
                  <span>0 — Seguro</span>
                  <span>100 — Crítico</span>
                </div>
              </div>

              {/* Conteo por severidad */}
              <div className="mt-4 flex flex-wrap gap-2">
                {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
                  <div
                    key={sev}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0A0A0A] border border-[#333333]"
                  >
                    <span className={`w-2 h-2 rounded-full ${severityStyle[sev].dot}`} />
                    <span className="text-[11px] font-mono text-[#888888] uppercase">{severityLabel(sev)}</span>
                    <span className={`text-sm font-black ml-1 ${
                      sev === "critical" || sev === "high"
                        ? "text-[#FF3333]"
                        : sev === "medium"
                        ? "text-[#A3A3A3]"
                        : "text-[#666666]"
                    }`}>
                      {counts[sev] || 0}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Gauge */}
            <div className="flex items-center md:items-start justify-center md:justify-end w-full">
              <div className="w-full sm:w-auto max-w-[240px] bg-[#0A0A0A]/90 rounded-2xl border border-[#333333] p-4 sm:p-5 flex flex-col items-center gap-4 shadow-xl">
                <RiskGauge score={result.riskScore} grade={result.grade} verdict={result.verdict} />
                <div className="w-full space-y-1.5 text-[11px] font-mono">
                  <div className="flex justify-between text-[#666666]">
                    <span>Motor</span>
                    <span className="text-white">{result.isLive ? "ThreatIntel v1.0" : "Heurística v0.1"}</span>
                  </div>
                  <div className="flex justify-between text-[#666666]">
                    <span>Fuentes</span>
                    <span className="text-white">{result.isLive ? "APIs en Vivo" : "Simuladas"}</span>
                  </div>
                  <div className="flex justify-between text-[#666666]">
                    <span>Verificación</span>
                    <span className="text-white">{result.isLive ? "100% Real" : "Demo"}</span>
                  </div>
                  <div className="pt-2 border-t border-[#222222]">
                    <VerificationBadge result={result} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Hallazgos ── */}
      <div className="rounded-2xl border border-[#333333] bg-[#121212]/80 overflow-hidden shadow-xl max-w-full box-border">
        <div className="px-4 sm:px-5 py-3.5 sm:py-4 border-b border-[#333333] flex items-center justify-between bg-[#0E0E0E]">
          <h2 className="text-xs sm:text-sm font-bold tracking-widest text-white uppercase">HALLAZGOS</h2>
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-[#1A1A1A] border border-[#333333] text-[#A3A3A3]">
            {result.findings.length} total
          </span>
        </div>
        <div className="p-3 sm:p-4">
          <FindingsAccordion result={result} />
        </div>
      </div>

      {/* ── Evidencia técnica (tabs) ── */}
      <EvidenceTabs result={result} />

      {/* ── Recomendaciones ── */}
      <div className="rounded-2xl border border-[#333333] bg-[#121212]/80 p-4 sm:p-6 shadow-xl max-w-full box-border">
        <h3 className="text-xs font-bold tracking-widest text-[#A3A3A3] mb-4 uppercase">RECOMENDACIONES</h3>
        <ul className="space-y-3">
          {result.recommendations.map((r, i) => (
            <li key={i} className="flex gap-3 text-xs sm:text-sm text-[#D4D4D4]">
              <span className="mt-0.5 w-6 h-6 rounded-full bg-white/10 border border-white/20 flex items-center justify-center text-white text-xs font-bold shrink-0">
                {i + 1}
              </span>
              <span className="leading-relaxed">{r}</span>
            </li>
          ))}
        </ul>
        <div className="mt-5 rounded-xl bg-[#1A1A1A] border border-[#333333] p-3.5 sm:p-4 flex gap-3">
          <span className="text-white text-base shrink-0">ℹ</span>
          <p className="text-xs leading-relaxed text-[#A3A3A3]">
            <span className="font-bold text-white">Seguridad y Privacidad Garantizada: </span>
            SecScanner analiza amenazas en tiempo real mediante correlación multi-fuente, inteligencia en vivo y análisis estático local. Tus consultas se procesan bajo arquitectura local-first: no se almacenan ni se comparten con bases de datos externas. Para incidentes confirmados, aplica de inmediato los IoCs y medidas de contención sugeridas.
          </p>
        </div>
      </div>

      {/* Footer del reporte */}
      <div className="text-center text-[11px] font-mono text-[#555555] pb-2">
        SecScanner Engine {result.isLive ? "v1.0 (Live)" : "v0.1"} · {result.scanDurationMs} ms · {result.isLive ? "Threat Intelligence en Vivo + Heurística" : "Heurística + YARA + Reputación"}
      </div>

    </div>
  );
}
