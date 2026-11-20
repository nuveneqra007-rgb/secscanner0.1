import { Finding, TechnicalEvidence } from "../types";

export interface VirusTotalServiceResult {
  detections?: TechnicalEvidence["vtDetections"];
  maliciousCount: number;
  suspiciousCount: number;
  totalEngines: number;
  reputation: number;
  tags: string[];
  findings: Finding[];
  riskContribution: number;
}

/**
 * Genera el identificador url_id en Base64URL sin padding requerido por la API v3 de VirusTotal.
 */
function getUrlId(url: string): string {
  return Buffer.from(url.trim()).toString("base64url");
}

/**
 * Consulta pasiva contra 70+ motores antivirus en VirusTotal API v3 (Hashes, URLs, Dominios, IPs).
 */
export async function queryVirusTotal(
  indicator: string,
  type: "hash" | "url" | "domain" | "ip"
): Promise<VirusTotalServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    findings.push({
      id: "vt-no-key",
      severity: "info",
      title: "VirusTotal no configurado",
      description: "Clave VIRUSTOTAL_API_KEY no encontrada en las variables de entorno.",
    });
    return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
  }

  // Determinar endpoint según el tipo de indicador
  let endpoint = "";
  const trimmed = indicator.trim();

  if (type === "hash") {
    endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(trimmed.toLowerCase())}`;
  } else if (type === "ip") {
    endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(trimmed.split(":")[0])}`;
  } else if (type === "domain") {
    endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(trimmed.toLowerCase())}`;
  } else {
    // type === "url"
    endpoint = `https://www.virustotal.com/api/v3/urls/${getUrlId(trimmed)}`;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const resp = await fetch(endpoint, {
      signal: controller.signal,
      headers: {
        "x-apikey": apiKey,
        "Accept": "application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (resp.status === 404) {
      findings.push({
        id: "vt-not-found",
        severity: "info",
        title: "No catalogado en VirusTotal",
        description: "El recurso aún no ha sido analizado por la comunidad de VirusTotal.",
      });
      return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
    }

    if (resp.status === 429) {
      findings.push({
        id: "vt-rate-limited",
        severity: "info",
        title: "Límite de cuota de VirusTotal alcanzado (429)",
        description: "Se ha alcanzado el límite de 4 consultas por minuto o 500 por día de la cuenta gratuita.",
      });
      return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
    }

    if (!resp.ok) {
      findings.push({
        id: "vt-http-error",
        severity: "info",
        title: "Error de consulta en VirusTotal",
        description: `VirusTotal respondió con estado HTTP ${resp.status}.`,
      });
      return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json: any = await resp.json();
    const attributes = json.data?.attributes;

    if (!attributes) {
      return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
    }

    const stats = attributes.last_analysis_stats || {};
    const maliciousCount = Number(stats.malicious) || 0;
    const suspiciousCount = Number(stats.suspicious) || 0;
    const harmlessCount = Number(stats.harmless) || 0;
    const undetectedCount = Number(stats.undetected) || 0;
    const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;
    const communityReputation = Number(attributes.reputation) || 0;
    const tags: string[] = Array.isArray(attributes.tags) ? attributes.tags : [];

    // Parsear detecciones específicas de motores
    const rawResults = attributes.last_analysis_results || {};
    const detections: NonNullable<TechnicalEvidence["vtDetections"]> = [];

    for (const [engineName, res] of Object.entries(rawResults)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const entry = res as any;
      if (entry && (entry.category === "malicious" || entry.category === "suspicious")) {
        detections.push({
          engine: engineName,
          result: entry.result || entry.category,
        });
      }
    }

    // Evaluación de Hallazgos y Riesgo
    if (maliciousCount >= 5) {
      const topEngines = detections.slice(0, 4).map(d => `${d.engine} (${d.result})`).join(", ");
      findings.push({
        id: "vt-critical-malicious",
        severity: "critical",
        title: `Detectado como malicioso por ${maliciousCount} motores en VirusTotal`,
        description: `Confirmación positiva de amenaza activa en ${maliciousCount} de ${totalEngines} motores de seguridad. Detecciones: ${topEngines}${detections.length > 4 ? "..." : ""}.`,
        evidence: `VirusTotal: ${maliciousCount}/${totalEngines} detecciones`,
      });
      riskScore += Math.min(65, 30 + maliciousCount * 4);
    } else if (maliciousCount >= 1) {
      const topEngines = detections.map(d => `${d.engine}: ${d.result}`).join(", ");
      findings.push({
        id: "vt-moderate-malicious",
        severity: "high",
        title: `Detección sospechosa en VirusTotal (${maliciousCount} motor/es)`,
        description: `Motores con alerta: ${topEngines}.`,
        evidence: `VirusTotal: ${maliciousCount}/${totalEngines}`,
      });
      riskScore += 25 + maliciousCount * 10;
    } else if (suspiciousCount >= 2) {
      findings.push({
        id: "vt-suspicious-alert",
        severity: "medium",
        title: `Marcado como sospechoso por ${suspiciousCount} motores en VirusTotal`,
        description: "Varios motores clasifican el indicador como sospechoso o anómalo.",
      });
      riskScore += 15;
    } else if (totalEngines > 0) {
      findings.push({
        id: "vt-clean",
        severity: "info",
        title: `Limpio en VirusTotal (0/${totalEngines} detecciones)`,
        description: `Ninguno de los ${totalEngines} motores de seguridad detectó firmas maliciosas activas.`,
      });
    }

    return {
      detections,
      maliciousCount,
      suspiciousCount,
      totalEngines,
      reputation: communityReputation,
      tags,
      findings,
      riskContribution: riskScore,
    };
  } catch (err) {
    findings.push({
      id: "vt-connection-error",
      severity: "info",
      title: "Error al conectar con VirusTotal",
      description: err instanceof Error ? err.message : "Fallo de red",
    });
    return { maliciousCount: 0, suspiciousCount: 0, totalEngines: 0, reputation: 0, tags: [], findings, riskContribution: 0 };
  }
}
