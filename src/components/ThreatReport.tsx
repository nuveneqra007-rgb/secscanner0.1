"use client";
import { ScanResult, Severity } from "@/lib/types";
import { formatDate, severityLabel } from "@/lib/utils";
import { RiskGauge, RiskBar } from "./RiskGauge";

function SeverityBadge({ s }: { s: Severity }) {
  const map: Record<Severity, string> = {
    critical: "bg-red-500 text-white border-red-500",
    high: "bg-orange-500 text-white border-orange-500",
    medium: "bg-amber-400 text-black border-amber-400",
    low: "bg-sky-500 text-white border-sky-500",
    info: "bg-zinc-800 text-zinc-300 border-zinc-700",
  };
  return <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border ${map[s]}`}>{severityLabel(s)}</span>;
}

export function ThreatReport({ result, onNewScan }: { result: ScanResult; onNewScan?: () => void }) {
  const counts = result.findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const gradeColor = result.riskScore >= 75 ? "text-red-400 border-red-500/30 bg-red-500/10" : result.riskScore >= 40 ? "text-amber-400 border-amber-500/30 bg-amber-500/10" : "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";

  const copyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  };

  return (
    <div className="w-full max-w-[980px] mx-auto space-y-6">
      {/* Top bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">ID: {result.id.slice(0, 18).toUpperCase()}</span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">{formatDate(result.timestamp)}</span>
          <span className="px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800">{result.scanDurationMs} ms</span>
        </div>
        <div className="flex gap-2">
          {onNewScan && (
            <button onClick={onNewScan} className="px-4 py-2 rounded-xl bg-white text-black text-sm font-semibold hover:bg-zinc-100 transition">Nuevo análisis</button>
          )}
          <button onClick={copyJSON} className="px-4 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-sm font-medium text-zinc-200 hover:bg-zinc-800">Copiar JSON</button>
          <button onClick={()=> window.print()} className="px-4 py-2 rounded-xl bg-zinc-900 border border-zinc-800 text-sm font-medium text-zinc-200 hover:bg-zinc-800 hidden md:inline-flex">Imprimir</button>
        </div>
      </div>

      {/* Hero card */}
      <div className={`rounded-[20px] border overflow-hidden ${result.verdict==="malicious" ? "border-red-500/30 bg-gradient-to-br from-red-950/20 via-zinc-900 to-zinc-900" : result.verdict==="suspicious" ? "border-amber-500/30 bg-gradient-to-br from-amber-950/20 via-zinc-900 to-zinc-900" : "border-emerald-500/30 bg-gradient-to-br from-emerald-950/15 via-zinc-900 to-zinc-900"}`}>
        <div className="p-6 md:p-8">
          <div className="grid md:grid-cols-[1fr_200px] gap-8">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-3">
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${result.verdict==="malicious" ? "bg-red-500 text-white border-red-500" : result.verdict==="suspicious" ? "bg-amber-500 text-black border-amber-500" : "bg-emerald-500 text-white border-emerald-500"}`}>
                  {result.verdict==="malicious" ? "● MALICIOSO" : result.verdict==="suspicious" ? "● SOSPECHOSO" : "● LIMPIO"}
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-mono bg-zinc-800 border border-zinc-700 text-zinc-300">{result.type.toUpperCase()} • Confianza: {result.confidence}</span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-widest border ${gradeColor}`}>GRADO {result.grade}</span>
              </div>

              <h1 className="text-xl md:text-2xl font-semibold text-white break-all leading-tight">{result.normalizedInput}</h1>
              <p className="mt-3 text-sm leading-relaxed text-zinc-300 max-w-[680px]">{result.summary}</p>

              <div className="mt-5">
                <RiskBar score={result.riskScore} />
                <div className="flex justify-between mt-1.5 text-[10px] font-mono tracking-widest text-zinc-500">
                  <span>0 — Seguro</span><span>100 — Crítico</span>
                </div>
              </div>

              <div className="mt-5 grid grid-cols-5 gap-2">
                {(["critical","high","medium","low","info"] as Severity[]).map(sev => (
                  <div key={sev} className="rounded-xl bg-zinc-900 border border-zinc-800 p-3 text-center">
                    <div className="text-[10px] tracking-widest font-bold text-zinc-500">{severityLabel(sev)}</div>
                    <div className={`text-xl font-black mt-1 ${sev==="critical"?"text-red-400": sev==="high"?"text-orange-400": sev==="medium"?"text-amber-400": sev==="low"?"text-sky-400":"text-zinc-400"}`}>{counts[sev] || 0}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col items-center justify-start bg-zinc-950/60 rounded-2xl border border-zinc-800 p-6">
              <RiskGauge score={result.riskScore} grade={result.grade} verdict={result.verdict} />
              <div className="mt-4 w-full space-y-2 text-xs font-mono">
                <div className="flex justify-between text-zinc-500"><span>Motor</span><span className="text-zinc-300">Heurística v2.4</span></div>
                <div className="flex justify-between text-zinc-500"><span>Reglas YARA</span><span className="text-zinc-300">240</span></div>
                <div className="flex justify-between text-zinc-500"><span>Feeds</span><span className="text-zinc-300">MISP + OTX</span></div>
                <div className="flex justify-between text-zinc-500"><span>TTL</span><span className="text-zinc-300">24h</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/60 backdrop-blur">
        <div className="p-6 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-bold tracking-widest text-zinc-100">HALLAZGOS DETALLADOS</h2>
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300">{result.findings.length} hallazgos</span>
        </div>
        <div className="divide-y divide-zinc-800">
          {result.findings.map(f => (
            <div key={f.id} className="p-5 md:p-6 flex gap-4 hover:bg-zinc-900/50 transition">
              <div className="hidden sm:block mt-1">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center border text-xs font-black
                  ${f.severity==="critical" ? "bg-red-500 border-red-500 text-white" : f.severity==="high" ? "bg-orange-500 border-orange-500 text-white" : f.severity==="medium" ? "bg-amber-400 border-amber-400 text-black" : f.severity==="low" ? "bg-sky-500 border-sky-500 text-white" : "bg-zinc-800 border-zinc-700 text-zinc-400"}`}>
                  {f.severity==="critical" ? "!" : f.severity==="high" ? "▲" : f.severity==="medium" ? "◐" : f.severity==="low" ? "●" : "i"}
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <SeverityBadge s={f.severity} />
                  <h3 className="text-sm font-semibold text-white">{f.title}</h3>
                  {f.mitre && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-400 border border-violet-500/20">{f.mitre}</span>}
                  {f.cwe && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">{f.cwe}</span>}
                </div>
                <p className="text-sm leading-relaxed text-zinc-300">{f.description}</p>
                {f.evidence && (
                  <div className="mt-3 rounded-xl bg-zinc-950 border border-zinc-800 p-3">
                    <div className="text-[10px] tracking-widest font-bold text-zinc-500 mb-1">EVIDENCIA TÉCNICA</div>
                    <div className="text-xs font-mono text-zinc-300 break-all leading-relaxed">{f.evidence}</div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technical evidence grid */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* WHOIS / DNS / SSL */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
          <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">EVIDENCIA TÉCNICA</h3>
          {result.evidence.whois && (
            <div className="mb-5">
              <div className="text-xs font-semibold text-zinc-200 mb-2">WHOIS & Dominio</div>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between"><span className="text-zinc-500">Registrar</span><span className="text-zinc-300">{result.evidence.whois.registrar}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Creado</span><span className="text-zinc-300">{result.evidence.whois.created?.slice(0,10)} ({result.evidence.whois.ageDays} días)</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Expira</span><span className="text-zinc-300">{result.evidence.whois.expires?.slice(0,10)}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">NS</span><span className="text-zinc-300 truncate ml-4 text-right">{result.evidence.dns?.ns?.join(", ")}</span></div>
              </div>
            </div>
          )}
          {result.evidence.ssl && (
            <div className="mb-5">
              <div className="text-xs font-semibold text-zinc-200 mb-2">TLS / Certificado</div>
              <div className={`rounded-xl border p-4 space-y-1.5 text-xs font-mono ${result.evidence.ssl.expired ? "bg-red-950/20 border-red-900" : "bg-zinc-950 border-zinc-800"}`}>
                <div className="flex justify-between"><span className="text-zinc-500">Emisor</span><span className="text-zinc-300 text-right ml-4 truncate">{result.evidence.ssl.issuer}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Sujeto</span><span className="text-zinc-300">{result.evidence.ssl.subject}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Válido hasta</span><span className={result.evidence.ssl.expired ? "text-red-400" : "text-emerald-400"}>{result.evidence.ssl.validTo?.slice(0,10)} ({result.evidence.ssl.daysUntilExpiry}d)</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">SANs</span><span className="text-zinc-300">{result.evidence.ssl.sans?.join(", ")}</span></div>
              </div>
            </div>
          )}
          {result.evidence.dns && result.evidence.dns.a && (
            <div>
              <div className="text-xs font-semibold text-zinc-200 mb-2">DNS & Infraestructura</div>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 space-y-1.5 text-xs font-mono">
                <div className="flex justify-between"><span className="text-zinc-500">A</span><span className="text-cyan-400">{result.evidence.dns.a.join(", ")}</span></div>
                {result.evidence.dns.mx && result.evidence.dns.mx.length>0 && <div className="flex justify-between"><span className="text-zinc-500">MX</span><span className="text-zinc-300 text-right ml-4 truncate">{result.evidence.dns.mx.join(", ")}</span></div>}
                <div className="flex justify-between"><span className="text-zinc-500">TXT</span><span className="text-zinc-300 text-right ml-4 truncate">{result.evidence.dns.txt?.join(" | ")}</span></div>
                {result.evidence.reverseDns && <div className="flex justify-between"><span className="text-zinc-500">PTR</span><span className="text-zinc-300">{result.evidence.reverseDns}</span></div>}
              </div>
            </div>
          )}
          {result.evidence.httpHeaders && (
            <div className="mt-5">
              <div className="text-xs font-semibold text-zinc-200 mb-2">Cabeceras HTTP</div>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 max-h-[220px] overflow-auto">
                <div className="space-y-1 text-[11px] font-mono">
                  {Object.entries(result.evidence.httpHeaders).filter(([,v])=> v).map(([k,v])=>(
                    <div key={k} className="flex gap-2"><span className="text-zinc-500 shrink-0">{k}:</span><span className="text-zinc-300 break-all">{v}</span></div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {result.evidence.redirectChain && result.evidence.redirectChain.length>1 && (
            <div className="mt-5">
              <div className="text-xs font-semibold text-zinc-200 mb-2">Cadena de redirecciones</div>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 space-y-2">
                {result.evidence.redirectChain.map((r,i)=>(
                  <div key={i} className="flex gap-3 text-xs font-mono">
                    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-bold h-fit ${r.status===200 ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/20" : "bg-amber-500/15 text-amber-400 border-amber-500/20"}`}>{r.status}</span>
                    <span className="text-zinc-300 break-all">{r.url}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Second column: Geo / Ports / File */}
        <div className="space-y-6">
          {result.evidence.geolocation && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">GEOLOCALIZACIÓN & ASN</h3>
              <div className="flex gap-4">
                <div className="w-12 h-12 rounded-xl bg-zinc-800 border border-zinc-700 flex items-center justify-center text-lg">{result.evidence.geolocation.countryCode==="DE"?"🇩🇪":result.evidence.geolocation.countryCode==="RU"?"🇷🇺":result.evidence.geolocation.countryCode==="US"?"🇺🇸":"🌐"}</div>
                <div>
                  <div className="text-sm font-semibold text-white">{result.evidence.geolocation.city}, {result.evidence.geolocation.country}</div>
                  <div className="text-xs font-mono text-zinc-400">{result.evidence.geolocation.lat.toFixed(4)}, {result.evidence.geolocation.lon.toFixed(4)} • {result.evidence.geolocation.isp}</div>
                  <div className="mt-2 text-xs font-mono px-2.5 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 inline-block">{result.evidence.geolocation.asn}</div>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-3"><div className="text-zinc-500">Organización</div><div className="text-zinc-300 mt-1">{result.evidence.geolocation.org}</div></div>
                <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-3"><div className="text-zinc-500">Región</div><div className="text-zinc-300 mt-1">{result.evidence.geolocation.region}</div></div>
              </div>
            </div>
          )}

          {result.evidence.reputation && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">REPUTACIÓN</h3>
              <div className="flex items-center gap-4 mb-4">
                <div className={`w-16 h-16 rounded-2xl flex flex-col items-center justify-center border ${result.evidence.reputation.abuseScore>70 ? "bg-red-500/15 border-red-500/30 text-red-400" : result.evidence.reputation.abuseScore>30 ? "bg-amber-500/15 border-amber-500/30 text-amber-400" : "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"}`}>
                  <span className="text-xl font-black">{result.evidence.reputation.abuseScore}</span>
                  <span className="text-[9px] tracking-widest">ABUSE</span>
                </div>
                <div className="text-xs font-mono text-zinc-400">
                  <div><span className="text-zinc-300 font-bold">{result.evidence.reputation.totalReports}</span> reportes (90d)</div>
                  <div>Último: {result.evidence.reputation.lastReported?.slice(0,10)}</div>
                </div>
              </div>
              <div className="space-y-2">
                {result.evidence.reputation.blacklists.map(b=>(
                  <div key={b.name} className="flex items-center justify-between rounded-xl bg-zinc-950 border border-zinc-800 px-4 py-2.5">
                    <span className="text-xs font-medium text-zinc-300">{b.name}</span>
                    <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border ${b.listed ? "bg-red-500 text-white border-red-500" : "bg-emerald-500/15 text-emerald-400 border-emerald-500/20"}`}>{b.listed ? "LISTADO" : "LIMPIO"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.evidence.ports && result.evidence.ports.length>0 && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">PUERTOS ABIERTOS</h3>
              <div className="space-y-2">
                {result.evidence.ports.map(p=>(
                  <div key={p.port} className="flex items-center justify-between rounded-xl bg-zinc-950 border border-zinc-800 px-4 py-3">
                    <div>
                      <div className="text-sm font-mono font-bold text-white">{p.port}<span className="text-zinc-500 font-normal">/tcp</span></div>
                      <div className="text-xs text-zinc-500">{p.service}</div>
                    </div>
                    <span className={`text-[10px] font-bold tracking-widest px-2.5 py-1 rounded-full border ${p.risk==="critical" ? "bg-red-500 text-white border-red-500" : p.risk==="high" ? "bg-orange-500 text-white border-orange-500" : p.risk==="medium" ? "bg-amber-400 text-black border-amber-400" : "bg-sky-500 text-white border-sky-500"}`}>{p.risk.toUpperCase()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.evidence.fileInfo && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">ARCHIVO / HASH</h3>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 p-4 space-y-2 text-xs font-mono">
                <div className="flex justify-between"><span className="text-zinc-500">Nombre</span><span className="text-zinc-300 ml-4 truncate">{result.evidence.fileInfo.name}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Tamaño</span><span className="text-zinc-300">{result.evidence.fileInfo.size}</span></div>
                <div className="flex justify-between"><span className="text-zinc-500">Tipo</span><span className="text-zinc-300 text-right ml-4">{result.evidence.fileInfo.type}</span></div>
                <div className="pt-3 border-t border-zinc-800 space-y-1.5">
                  <div><span className="text-zinc-500">MD5</span><div className="text-cyan-400 break-all">{result.evidence.fileInfo.md5}</div></div>
                  <div><span className="text-zinc-500">SHA1</span><div className="text-cyan-400 break-all">{result.evidence.fileInfo.sha1}</div></div>
                  <div><span className="text-zinc-500">SHA256</span><div className="text-cyan-400 break-all">{result.evidence.fileInfo.sha256}</div></div>
                  {result.evidence.ssdeep && <div><span className="text-zinc-500">ssdeep</span><div className="text-zinc-400 break-all">{result.evidence.ssdeep}</div></div>}
                  {result.evidence.fileInfo.entropy && <div className="flex justify-between"><span className="text-zinc-500">Entropía</span><span className="text-amber-400">{result.evidence.fileInfo.entropy.toFixed(2)}/8.0</span></div>}
                </div>
              </div>
              {result.evidence.vtDetections && result.evidence.vtDetections.length>0 && (
                <div className="mt-4">
                  <div className="text-xs font-semibold text-zinc-200 mb-2">VirusTotal</div>
                  <div className="rounded-xl bg-zinc-950 border border-zinc-800 divide-y divide-zinc-800">
                    {result.evidence.vtDetections.map((v,i)=>(
                      <div key={i} className="flex justify-between px-4 py-2 text-xs font-mono">
                        <span className="text-zinc-400">{v.engine}</span>
                        <span className={v.result==="Clean" ? "text-emerald-400" : "text-red-400"}>{v.result}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {result.evidence.permissions && result.evidence.permissions.length>0 && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">PERMISOS APK</h3>
              <div className="space-y-2 max-h-[360px] overflow-auto pr-1">
                {result.evidence.permissions.map(p=>(
                  <div key={p.name} className="rounded-xl bg-zinc-950 border border-zinc-800 p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`w-2 h-2 rounded-full ${p.severity==="critical" ? "bg-red-500" : p.severity==="high" ? "bg-orange-500" : p.severity==="medium" ? "bg-amber-500" : "bg-sky-500"}`} />
                      <span className="text-xs font-mono font-semibold text-zinc-200 truncate">{p.name}</span>
                    </div>
                    <div className="text-xs text-zinc-400 leading-relaxed">{p.description}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {result.evidence.iocs && result.evidence.iocs.length>0 && (
            <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
              <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">INDICADORES (IoCs)</h3>
              <div className="rounded-xl bg-zinc-950 border border-zinc-800 overflow-hidden">
                <table className="w-full text-xs font-mono">
                  <thead className="bg-zinc-900 text-zinc-500"><tr><th className="text-left px-3 py-2 font-medium">Tipo</th><th className="text-left px-3 py-2 font-medium">Valor</th></tr></thead>
                  <tbody className="divide-y divide-zinc-800">
                    {result.evidence.iocs.map((ioc,idx)=>(
                      <tr key={idx} className="hover:bg-zinc-900/50"><td className="px-3 py-2 text-zinc-500">{ioc.type}</td><td className="px-3 py-2 text-cyan-400 break-all">{ioc.value}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recommendations */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
        <h3 className="text-xs font-bold tracking-widest text-zinc-400 mb-4">RECOMENDACIONES DEL ANALISTA</h3>
        <ul className="space-y-3">
          {result.recommendations.map((r,i)=>(
            <li key={i} className="flex gap-3 text-sm text-zinc-300">
              <span className="mt-1 w-6 h-6 rounded-full bg-cyan-500/15 border border-cyan-500/20 flex items-center justify-center text-cyan-400 text-xs font-bold shrink-0">{i+1}</span>
              <span className="leading-relaxed">{r}</span>
            </li>
          ))}
        </ul>
        <div className="mt-6 rounded-xl bg-amber-500/10 border border-amber-500/20 p-4 flex gap-3">
          <span className="text-amber-400 text-lg">⚠</span>
          <div className="text-xs leading-relaxed text-amber-200/80">
            <span className="font-bold text-amber-300">Aviso legal:</span> Este análisis es heurístico y con fines educativos/portafolio. No sustituye un sandbox dinámico ni la validación de un analista SOC. Para incidentes reales, escale al CERT correspondiente.
          </div>
        </div>
      </div>

      <div className="text-center text-xs font-mono text-zinc-600 pb-4">
        ThreatScan Engine v2.4 • Heurística + Reputación + YARA • Tiempo de análisis {result.scanDurationMs} ms • Siguiente purga de caché en 23h 42m
      </div>
    </div>
  );
}
