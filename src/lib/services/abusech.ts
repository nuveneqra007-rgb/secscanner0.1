import { Finding } from "../types";

export interface AbuseChServiceResult {
  found: boolean;
  source?: "urlhaus" | "threatfox" | "malwarebazaar";
  threat?: string;
  signature?: string;
  tags?: string[];
  findings: Finding[];
  riskContribution: number;
}

/**
 * Consulta URLhaus para verificar si una URL distribuye malware o exploits.
 */
async function queryUrlhaus(url: string, authKey: string): Promise<AbuseChServiceResult | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const bodyParams = new URLSearchParams({ url: url.trim() });

    const resp = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      body: bodyParams,
      signal: controller.signal,
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (!resp.ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    if (data.query_status === "ok") {
      const threat = data.threat || "Distribución de Malware";
      const tags: string[] = Array.isArray(data.tags) ? data.tags : [];
      const urlStatus = data.url_status || "activo";

      const findings: Finding[] = [
        {
          id: "abusech-urlhaus-hit",
          severity: "critical",
          title: `URL catalogada en URLhaus (${threat})`,
          description: `Identificada como vector de descarga de malware por la comunidad de abuse.ch. Estado actual de la URL: ${urlStatus}.`,
          evidence: `Tags: ${tags.join(", ") || "N/A"} | Estado: ${urlStatus}`,
        },
      ];

      return {
        found: true,
        source: "urlhaus",
        threat,
        tags,
        findings,
        riskContribution: 55,
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Consulta ThreatFox para rastrear Indicadores de Compromiso (IOCs) activos.
 */
async function queryThreatFox(indicator: string, authKey: string): Promise<AbuseChServiceResult | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
      body: JSON.stringify({
        query: "search_ioc",
        search_term: indicator.trim(),
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!resp.ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length > 0) {
      const ioc = data.data[0];
      const threatType = ioc.threat_type_desc || ioc.threat_type || "Amenaza activa";
      const malware = ioc.malware_printable || ioc.malware || "Malware no especificado";
      const confidence = Number(ioc.confidence_level) || 100;
      const tags: string[] = Array.isArray(ioc.tags) ? ioc.tags : [];

      const findings: Finding[] = [
        {
          id: "abusech-threatfox-hit",
          severity: "critical",
          title: `IOC confirmado en ThreatFox: ${malware}`,
          description: `Indicador de compromiso registrado como '${threatType}' (Confianza de detección: ${confidence}%).`,
          evidence: `Familia: ${malware} | Tipo: ${threatType} | Tags: ${tags.join(", ") || "N/A"}`,
        },
      ];

      return {
        found: true,
        source: "threatfox",
        threat: threatType,
        signature: malware,
        tags,
        findings,
        riskContribution: Math.min(60, Math.round(confidence * 0.6)),
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Consulta MalwareBazaar para verificar muestras de malware asociadas a un hash.
 */
async function queryMalwareBazaar(hash: string, authKey: string): Promise<AbuseChServiceResult | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const bodyParams = new URLSearchParams({
      query: "get_info",
      hash: hash.trim().toLowerCase(),
    });

    const resp = await fetch("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      body: bodyParams,
      signal: controller.signal,
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (!resp.ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length > 0) {
      const sample = data.data[0];
      const signature = sample.signature || "Muestra de Malware";
      const fileType = sample.file_type_mime || sample.file_type || "Binario";
      const tags: string[] = Array.isArray(sample.tags) ? sample.tags : [];

      const findings: Finding[] = [
        {
          id: "abusech-malwarebazaar-hit",
          severity: "critical",
          title: `Firma confirmada en MalwareBazaar: ${signature}`,
          description: `El hash coincide con una muestra catalogada en MalwareBazaar (${fileType}).`,
          evidence: `Firma: ${signature} | Tipo MIME: ${fileType} | Tags: ${tags.join(", ") || "N/A"}`,
        },
      ];

      return {
        found: true,
        source: "malwarebazaar",
        signature,
        tags,
        findings,
        riskContribution: 60,
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Orquestador unificado de consultas contra la suite de inteligencia de amenazas de abuse.ch.
 */
export async function checkAbuseCh(
  indicator: string,
  type: "url" | "domain" | "ip" | "hash"
): Promise<AbuseChServiceResult> {
  const authKey = process.env.ABUSECH_AUTH_KEY;
  if (!authKey) {
    return {
      found: false,
      findings: [],
      riskContribution: 0,
    };
  }

  // Bifurcar consulta según tipo de indicador
  if (type === "hash") {
    const [mbResult, tfResult] = await Promise.all([
      queryMalwareBazaar(indicator, authKey),
      queryThreatFox(indicator, authKey),
    ]);
    return mbResult || tfResult || { found: false, findings: [], riskContribution: 0 };
  }

  if (type === "url") {
    const [uhResult, tfResult] = await Promise.all([
      queryUrlhaus(indicator, authKey),
      queryThreatFox(indicator, authKey),
    ]);
    return uhResult || tfResult || { found: false, findings: [], riskContribution: 0 };
  }

  // Dominio o IP
  const tfResult = await queryThreatFox(indicator, authKey);
  return tfResult || { found: false, findings: [], riskContribution: 0 };
}
