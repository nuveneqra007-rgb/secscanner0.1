"use client";
import { useState } from "react";
import { ScanResult, Severity } from "@/lib/types";
import { formatDate, severityLabel } from "@/lib/utils";
import { RiskGauge, RiskBar } from "./RiskGauge";

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const severityStyle: Record<Severity, { badge: string; icon: string; row: string; dot: string }> = {
  critical: {
    badge: "bg-red-500 text-white border-red-500",
    icon:  "bg-red-500 border-red-500 text-white",
    row:   "border-l-red-500",
    dot:   "bg-red-500",
  },
  high: {
    badge: "bg-orange-500 text-white border-orange-500",
    icon:  "bg-orange-500 border-orange-500 text-white",
    row:   "border-l-orange-500",
    dot:   "bg-orange-500",
  },
  medium: {
    badge: "bg-amber-400 text-black border-amber-400",
    icon:  "bg-amber-400 border-amber-400 text-black",
    row:   "border-l-amber-400",
    dot:   "bg-amber-400",
  },
  low: {
    badge: "bg-sky-500 text-white border-sky-500",
    icon:  "bg-sky-500 border-sky-500 text-white",
    row:   "border-l-sky-500",
    dot:   "bg-sky-500",
  },
  info: {
    badge: "bg-zinc-700 text-zinc-300 border-zinc-600",
    icon:  "bg-zinc-800 border-zinc-700 text-zinc-400",
    row:   "border-l-zinc-600",
    dot:   "bg-zinc-500",
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

// ── Sub-componentes ───────────────────────────────────────────────────────────

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
    <div className="flex justify-between gap-3 text-xs font-mono py-1.5 border-b border-zinc-800/60 last:border-0">
      <span className="text-zinc-500 shrink-0">{label}</span>
      <span className={`text-right break-all ${accent ?? "text-zinc-300"}`}>{value}</span>
    </div>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 space-y-0">
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
          <div key={sev} className="rounded-xl border border-zinc-800 overflow-hidden">
            {/* Cabecera de sección */}
            <button
              onClick={() => toggle(sev)}
              className="w-full flex items-center justify-between px-5 py-3.5 bg-zinc-900/80 hover:bg-zinc-900 transition"
            >
              <div className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${st.dot}`} />
                <span className="text-sm font-bold text-zinc-200">{severityLabel(sev)}</span>
                <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${st.badge}`}>
                  {items.length}
                </span>
              </div>
              <svg
                width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="#71717a" strokeWidth="2"
                className={`transition-transform ${isOpen ? "rotate-180" : ""}`}
              >
                <path d="M6 9l6 6 6-6" />
              </svg>
            </button>

            {/* Findings dentro */}
            {isOpen && (
              <div className="divide-y divide-zinc-800">
                {items.map((f) => {
                  const isExpanded = expandedIds.has(f.id);
                  return (
                    <div key={f.id} className={`border-l-2 ${st.row}`}>
                      {/* Fila del finding */}
                      <button
                        onClick={() => toggleFinding(f.id)}
                        className="w-full text-left flex items-start gap-4 px-5 py-4 hover:bg-zinc-900/40 transition"
                      >
                        <div className={`mt-0.5 w-7 h-7 rounded-lg flex items-center justify-center border text-[11px] font-black shrink-0 ${st.icon}`}>
                          {SEVERITY_ICONS[f.severity]}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <SeverityBadge s={f.severity} />
                            <span className="text-sm font-semibold text-white">{f.title}</span>
                            {f.mitre && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-400 border border-violet-500/20">
                                {f.mitre}
                              </span>
                            )}
                            {f.cwe && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">
                                {f.cwe}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-zinc-400 leading-relaxed line-clamp-2">{f.description}</p>
                        </div>
                        <svg
                          width="14" height="14" viewBox="0 0 24 24" fill="none"
                          stroke="#52525b" strokeWidth="2"
                          className={`mt-1 shrink-0 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                        >
                          <path d="M6 9l6 6 6-6" />
                        </svg>
                      </button>

                      {/* Evidencia expandida */}
                      {isExpanded && f.evidence && (
                        <div className="px-5 pb-4">
                          <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4">
                            <div className="text-[10px] tracking-widest font-bold text-zinc-600 mb-2">EVIDENCIA TÉCNICA</div>
                            <p className="text-xs font-mono text-zinc-300 break-all leading-relaxed">{f.evidence}</p>
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
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
      {/* Tab bar */}
      <div className="flex border-b border-zinc-800 overflow-x-auto">
        {availableTabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setActive(t.id)}
            className={`px-4 py-3 text-[11px] font-bold tracking-wider whitespace-nowrap transition-colors
              ${active === t.id
                ? "text-white border-b-2 border-cyan-500 -mb-px bg-zinc-900/60"
                : "text-zinc-500 hover:text-zinc-300"}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Contenido del tab activo */}
      <div className="p-5">

        {/* WHOIS & DNS */}
        {active === "whois" && (
          <div className="grid sm:grid-cols-2 gap-4">
            {ev.whois && (
              <div>
                <div className="text-xs font-semibold text-zinc-400 mb-2">WHOIS</div>
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
                <div className="text-xs font-semibold text-zinc-400 mb-2">DNS</div>
                <Panel>
                  <KV label="A"   value={ev.dns.a?.join(", ")}   accent="text-cyan-400" />
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
               accent={ev.ssl.expired ? "text-red-400" : "text-emerald-400"} />
            <KV label="SANs"        value={ev.ssl.sans?.join(", ")} />
            {ev.ssl.expired && (
              <div className="mt-3 rounded-lg bg-red-950/30 border border-red-900/50 px-3 py-2 text-xs text-red-300 font-mono">
                ⚠ Certificado expirado
              </div>
            )}
          </Panel>
        )}

        {/* Cabeceras HTTP */}
        {active === "headers" && ev.httpHeaders && (
          <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 max-h-64 overflow-auto">
            <div className="space-y-1.5 text-[11px] font-mono">
              {Object.entries(ev.httpHeaders)
                .filter(([, v]) => v)
                .map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-zinc-500 shrink-0">{k}:</span>
                    <span className="text-zinc-300 break-all">{v}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Redirecciones */}
        {active === "redirects" && ev.redirectChain && (
          <div className="space-y-2">
            {ev.redirectChain.map((r, i) => (
              <div key={i} className="flex gap-3 items-start rounded-xl bg-zinc-950 border border-zinc-800 px-4 py-3">
                <span className={`shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full border h-fit
                  ${r.status === 200
                    ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/20"
                    : "bg-amber-500/15 text-amber-400 border-amber-500/20"}`}>
                  {r.status}
                </span>
                <span className="text-xs font-mono text-zinc-300 break-all">{r.url}</span>
              </div>
            ))}
          </div>
        )}

        {/* Geolocalización */}
        {active === "geo" && ev.geolocation && (
          <div className="space-y-4">
            <div className="flex gap-4 items-center">
              <div className="w-12 h-12 rounded-xl bg-zinc-800 border border-zinc-700 flex items-center justify-center text-2xl shrink-0">
                🌐
              </div>
              <div>
                <div className="text-sm font-semibold text-white">
                  {ev.geolocation.city}, {ev.geolocation.country}
                </div>
                <div className="text-xs font-mono text-zinc-400 mt-0.5">
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
              <div className={`w-16 h-16 rounded-2xl flex flex-col items-center justify-center border shrink-0
                ${ev.reputation.abuseScore > 70
                  ? "bg-red-500/15 border-red-500/30 text-red-400"
                  : ev.reputation.abuseScore > 30
                  ? "bg-amber-500/15 border-amber-500/30 text-amber-400"
                  : "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"}`}>
                <span className="text-xl font-black">{ev.reputation.abuseScore}</span>
                <span className="text-[9px] tracking-widest">ABUSE</span>
              </div>
              <div className="text-xs font-mono text-zinc-400 space-y-1">
                <div><span className="text-zinc-200 font-bold">{ev.reputation.totalReports}</span> reportes (90d)</div>
                {ev.reputation.lastReported && (
                  <div>Último: {ev.reputation.lastReported.slice(0,10)}</div>
                )}
              </div>
            </div>
            {/* Blacklists */}
            <div className="space-y-2">
              {ev.reputation.blacklists.map((b) => (
                <div key={b.name} className="flex items-center justify-between rounded-xl bg-zinc-950 border border-zinc-800 px-4 py-2.5">
                  <span className="text-xs font-medium text-zinc-300">{b.name}</span>
                  <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border
                    ${b.listed
                      ? "bg-red-500 text-white border-red-500"
                      : "bg-emerald-500/15 text-emerald-400 border-emerald-500/20"}`}>
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
              <div key={p.port} className="flex items-center justify-between rounded-xl bg-zinc-950 border border-zinc-800 px-4 py-3">
                <div>
                  <span className="text-sm font-mono font-bold text-white">{p.port}</span>
                  <span className="text-zinc-500 font-mono text-sm">/tcp</span>
                  <span className="text-xs text-zinc-500 ml-3">{p.service}</span>
                </div>
                <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border
                  ${p.risk === "critical" ? "bg-red-500 text-white border-red-500"
                  : p.risk === "high"     ? "bg-orange-500 text-white border-orange-500"
                  : p.risk === "medium"   ? "bg-amber-400 text-black border-amber-400"
                  :                         "bg-sky-500 text-white border-sky-500"}`}>
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
                <KV label="Entropía" value={`${ev.fileInfo.entropy.toFixed(2)} / 8.0`} accent="text-amber-400" />
              )}
              <KV label="MD5"    value={ev.fileInfo.md5}    accent="text-cyan-400" />
              <KV label="SHA1"   value={ev.fileInfo.sha1}   accent="text-cyan-400" />
              <KV label="SHA256" value={ev.fileInfo.sha256} accent="text-cyan-400" />
              {ev.ssdeep && <KV label="ssdeep" value={ev.ssdeep} accent="text-zinc-400" />}
            </Panel>
            {ev.vtDetections && ev.vtDetections.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-zinc-400 mb-2">VirusTotal</div>
                <div className="rounded-xl bg-zinc-950 border border-zinc-800 divide-y divide-zinc-800">
                  {ev.vtDetections.map((v, i) => (
                    <div key={i} className="flex justify-between px-4 py-2 text-xs font-mono">
                      <span className="text-zinc-400">{v.engine}</span>
                      <span className={v.result === "Clean" ? "text-emerald-400" : "text-red-400"}>{v.result}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {ev.permissions && ev.permissions.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-zinc-400 mb-2">Permisos APK</div>
                <div className="space-y-2 max-h-64 overflow-auto pr-1">
                  {ev.permissions.map((p) => (
                    <div key={p.name} className="rounded-xl bg-zinc-950 border border-zinc-800 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-2 h-2 rounded-full ${
                          p.severity === "critical" ? "bg-red-500"
                          : p.severity === "high"   ? "bg-orange-500"
                          : p.severity === "medium" ? "bg-amber-500"
                          : "bg-sky-500"}`} />
                        <span className="text-xs font-mono font-semibold text-zinc-200 truncate">{p.name}</span>
                      </div>
                      <p className="text-xs text-zinc-500 leading-relaxed">{p.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* IoCs */}
        {active === "iocs" && ev.iocs && (
          <div className="rounded-xl bg-zinc-950 border border-zinc-800 overflow-hidden">
            <table className="w-full text-xs font-mono">
              <thead className="bg-zinc-900 text-zinc-500">
                <tr>
                  <th className="text-left px-4 py-2.5 font-medium">Tipo</th>
                  <th className="text-left px-4 py-2.5 font-medium">Valor</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {ev.iocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-zinc-900/50">
                    <td className="px-4 py-2.5 text-zinc-500 whitespace-nowrap">{ioc.type}</td>
                    <td className="px-4 py-2.5 text-cyan-400 break-all">{ioc.value}</td>
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
  const counts = result.findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const verdictStyle =
    result.verdict === "malicious"
      ? { ring: "border-red-500/30",    bg: "from-red-950/20",    badge: "bg-red-500 text-white border-red-500",    label: "● MALICIOSO" }
      : result.verdict === "suspicious"
      ? { ring: "border-amber-500/30",  bg: "from-amber-950/20",  badge: "bg-amber-500 text-black border-amber-500", label: "● SOSPECHOSO" }
      : { ring: "border-emerald-500/30",bg: "from-emerald-950/15",badge: "bg-emerald-500 text-white border-emerald-500", label: "● LIMPIO" };

  const gradeColor =
    result.riskScore >= 75 ? "text-red-400 border-red-500/30 bg-red-500/10"
    : result.riskScore >= 40 ? "text-amber-400 border-amber-500/30 bg-amber-500/10"
    : "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";

  const copyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  };

  return (
    <div className="w-full space-y-5">

      {/* ── Barra superior ── */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-zinc-500">
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
            ID: {result.id.slice(0, 16).toUpperCase()}
          </span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
            {formatDate(result.timestamp)}
          </span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">
            {result.scanDurationMs} ms
          </span>
        </div>
        <div className="flex gap-2">
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="px-4 py-2 rounded-lg bg-cyan-500 text-black text-sm font-bold hover:bg-cyan-400 transition"
            >
              Nuevo análisis
            </button>
          )}
          <button
            onClick={copyJSON}
            className="px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition"
          >
            Copiar JSON
          </button>
          <button
            onClick={() => window.print()}
            className="hidden md:inline-flex px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition"
          >
            Imprimir
          </button>
        </div>
      </div>

      {/* ── Hero card ── */}
      <div className={`rounded-2xl border overflow-hidden ${verdictStyle.ring} bg-gradient-to-br ${verdictStyle.bg} via-zinc-900 to-zinc-900`}>
        <div className="p-6 md:p-7">
          <div className="grid md:grid-cols-[1fr_180px] gap-6">
            <div className="min-w-0">
              {/* Badges de estado */}
              <div className="flex flex-wrap items-center gap-2 mb-3">
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${verdictStyle.badge}`}>
                  {verdictStyle.label}
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-mono bg-zinc-800 border border-zinc-700 text-zinc-300">
                  {result.type.toUpperCase()} · {result.confidence}
                </span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${gradeColor}`}>
                  GRADO {result.grade}
                </span>
              </div>

              {/* Indicador */}
              <h1 className="text-lg md:text-xl font-semibold text-white break-all leading-snug">
                {result.normalizedInput}
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-zinc-400 max-w-[640px]">
                {result.summary}
              </p>

              {/* Barra de riesgo */}
              <div className="mt-5">
                <RiskBar score={result.riskScore} />
                <div className="flex justify-between mt-1.5 text-[10px] font-mono tracking-widest text-zinc-600">
                  <span>0 — Seguro</span>
                  <span>100 — Crítico</span>
                </div>
              </div>

              {/* Conteo por severidad */}
              <div className="mt-4 flex flex-wrap gap-2">
                {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
                  <div
                    key={sev}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800"
                  >
                    <span className={`w-2 h-2 rounded-full ${severityStyle[sev].dot}`} />
                    <span className="text-[11px] font-mono text-zinc-400">{severityLabel(sev)}</span>
                    <span className={`text-sm font-black ml-1
                      ${sev === "critical" ? "text-red-400"
                      : sev === "high"     ? "text-orange-400"
                      : sev === "medium"   ? "text-amber-400"
                      : sev === "low"      ? "text-sky-400"
                      : "text-zinc-500"}`}>
                      {counts[sev] || 0}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Gauge */}
            <div className="flex items-start justify-center md:justify-end">
              <div className="bg-zinc-950/60 rounded-2xl border border-zinc-800 p-5 flex flex-col items-center gap-4">
                <RiskGauge score={result.riskScore} grade={result.grade} verdict={result.verdict} />
                <div className="w-full space-y-1.5 text-[11px] font-mono">
                  <div className="flex justify-between text-zinc-500">
                    <span>Motor</span>
                    <span className="text-zinc-300">Heurística v2.4</span>
                  </div>
                  <div className="flex justify-between text-zinc-500">
                    <span>Reglas</span>
                    <span className="text-zinc-300">240 YARA</span>
                  </div>
                  <div className="flex justify-between text-zinc-500">
                    <span>Feeds</span>
                    <span className="text-zinc-300">MISP + OTX</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Hallazgos ── */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-bold tracking-widest text-zinc-100">HALLAZGOS</h2>
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-400">
            {result.findings.length} total
          </span>
        </div>
        <div className="p-4">
          <FindingsAccordion result={result} />
        </div>
      </div>

      {/* ── Evidencia técnica (tabs) ── */}
      <EvidenceTabs result={result} />

      {/* ── Recomendaciones ── */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">RECOMENDACIONES</h3>
        <ul className="space-y-3">
          {result.recommendations.map((r, i) => (
            <li key={i} className="flex gap-3 text-sm text-zinc-300">
              <span className="mt-0.5 w-6 h-6 rounded-full bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center text-cyan-400 text-xs font-bold shrink-0">
                {i + 1}
              </span>
              <span className="leading-relaxed">{r}</span>
            </li>
          ))}
        </ul>
        <div className="mt-5 rounded-xl bg-amber-500/10 border border-amber-500/20 p-4 flex gap-3">
          <span className="text-amber-400 text-base shrink-0">⚠</span>
          <p className="text-xs leading-relaxed text-amber-200/80">
            <span className="font-bold text-amber-300">Aviso legal: </span>
            Este análisis es heurístico y con fines educativos. No sustituye un sandbox dinámico ni la validación de un analista SOC. Para incidentes reales, escala al CERT correspondiente.
          </p>
        </div>
      </div>

      {/* Footer del reporte */}
      <div className="text-center text-[11px] font-mono text-zinc-700 pb-2">
        ThreatScan Engine v2.4 · {result.scanDurationMs} ms · Heurística + YARA + Reputación
      </div>

    </div>
  );
}
