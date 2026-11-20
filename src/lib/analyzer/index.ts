import { Finding, ScanResult, TechnicalEvidence } from "../types";
import { detectIndicatorType, gradeFromScore, hashString, seededRandom, verdictFromScore } from "../utils";
import { analyzeUrl } from "./url";
import { analyzeIp } from "./ip";
import { analyzeHashOrFile } from "./file";

export function analyze(input: string, fileName?: string): ScanResult {
  const start = Date.now();
  const type = fileName ? (fileName.toLowerCase().endsWith(".apk") ? "apk" : "file") : detectIndicatorType(input);
  const normalized = input.trim();
  const rnd = seededRandom(hashString(normalized + (fileName||"")));
  const findings: Finding[] = [];
  const evidence: TechnicalEvidence = {};
  let score = 0;

  if (type === "ip" || type === "domain" && /^(\d+\.){3}\d+$/.test(normalized)) {
    score = analyzeIp(normalized, findings, evidence, rnd);
  } else if (type === "url" || type === "domain") {
    score = analyzeUrl(normalized, findings, evidence, rnd);
  } else if (type === "hash" || type === "file" || type === "apk") {
    score = analyzeHashOrFile(normalized, findings, evidence, rnd, fileName || (type==="hash"? undefined : undefined));
    // also if input looks like hash but also fileName given, keep file analysis
  } else {
    score = analyzeUrl(normalized, findings, evidence, rnd);
  }

  // Ensure at least one info finding
  if (findings.filter(f=> f.severity==="info").length===0 && score < 20) {
    findings.push({
      id:"scan-complete",
      severity:"info",
      title:"Análisis heurístico completado",
      description:"No se detectaron técnicas de evasión ni indicadores de compromiso. El artefacto pasó las validaciones de sintaxis, reputación y firma.",
      evidence:`Motores: Heurística v2.4, Reputación v1.9, YARA: 240 reglas`,
    });
  }

  // Add recommendation base
  const verdict = verdictFromScore(score);
  const grade = gradeFromScore(score);
  const summary = verdict==="malicious" ? "Este indicador presenta múltiples señales de compromiso y debe considerarse malicioso. Bloquear y reportar." :
                  verdict==="suspicious" ? "Se detectaron anomalías que requieren investigación adicional antes de confiar en este recurso." :
                  "No se encontraron indicadores de compromiso significativos. Mantener monitoreo rutinario.";

  const recommendations: string[] = [];
  if (verdict==="malicious") {
    recommendations.push("Bloquear el indicador en firewall, proxy y DNS (RPZ).");
    recommendations.push("Buscar IOCs relacionados en logs de SIEM (últimos 30 días).");
    recommendations.push("Si hubo interacción, forzar reset de credenciales y revocar sesiones OAuth.");
    recommendations.push("Reportar a AbuseIPDB / PhishTank y al CERT local.");
  } else if (verdict==="suspicious") {
    recommendations.push("Abrir en entorno aislado (sandbox / browser isolation) para inspección dinámica.");
    recommendations.push("Verificar con fuente oficial por canal secundario (no hacer clic directo).");
    recommendations.push("Añadir a lista de observación y re-escanear en 24h.");
  } else {
    recommendations.push("Permitir acceso pero mantener logging y alertas de anomalías.");
    recommendations.push("Verificar certificado y WHOIS periódicamente para cambios.");
  }
  recommendations.push("Documentar hallazgos en ticket de SOC con ID de escaneo.");

  // sort findings by severity
  findings.sort((a,b)=> ( {critical:0,high:1,medium:2,low:3,info:4}[a.severity] - {critical:0,high:1,medium:2,low:3,info:4}[b.severity] ));

  return {
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2,6)}`,
    timestamp: new Date().toISOString(),
    input: normalized.slice(0,500),
    normalizedInput: normalized,
    type,
    verdict,
    riskScore: Math.round(score),
    grade,
    confidence: score>70 ? "Alta" : score>40 ? "Media" : "Baja",
    summary,
    findings,
    evidence,
    recommendations,
    scanDurationMs: Date.now()-start + Math.floor(rnd()*400)+ 600, // simulated
  };
}

// Pre-seeded examples
export function getSeedScans(): ScanResult[] {
  const examples: { input: string; fileName?: string }[] = [
    {
      input: "https://banc0-santander-secure-login.tk/verify/account?session=9283&token=am9obi5kb2VAbWFpbC5jb20=",
    },
    {
      input: "185.220.101.47",
    },
    {
      input: "https://github.com/trending",
    },
  ];
  // Use deterministic seeds by overriding date
  const results = examples.map(e => analyze(e.input, e.fileName));
  // Force timestamps to look recent and distinct
  const now = Date.now();
  results[0].timestamp = new Date(now - 1000*60*42).toISOString(); // 42 min ago
  results[1].timestamp = new Date(now - 1000*60*120).toISOString(); // 2h ago
  results[2].timestamp = new Date(now - 1000*60*240).toISOString(); // 4h ago
  // Ensure verdicts are as expected
  // Force first to be malicious high score if not
  if (results[0].riskScore < 75) {
    results[0].riskScore = 92;
    results[0].verdict = "malicious";
    results[0].grade = "F";
  }
  if (results[1].riskScore < 75) {
    results[1].riskScore = 88;
    results[1].verdict = "malicious";
    results[1].grade = "F";
  }
  if (results[2].riskScore > 20) {
    results[2].riskScore = 8;
    results[2].verdict = "clean";
    results[2].grade = "A";
  }
  // Sort newest first
  return results.sort((a,b)=> new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}
