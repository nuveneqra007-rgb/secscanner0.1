import { Finding, TechnicalEvidence } from "../types";

export interface GeolocationServiceResult {
  geolocation?: TechnicalEvidence["geolocation"];
  reverseDns?: string;
  findings: Finding[];
  riskContribution: number;
}

/**
 * Consulta la geolocalización, ASN, ISP y Reverse DNS real de una IP pública vía ip-api.com (formato JSON).
 */
export async function geolocateIp(ip: string): Promise<GeolocationServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  const cleanIp = ip.trim().split(":")[0].replace(/^\[|\]$/g, "");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);

    const url = `https://ipwho.is/${encodeURIComponent(cleanIp)}`;

    const resp = await fetch(url, {
      signal: controller.signal,
      headers: {
        "Accept": "application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (!resp.ok) {
      findings.push({
        id: "geo-fetch-failed",
        severity: "info",
        title: "Consulta de geolocalización no disponible",
        description: `El servicio de geolocalización respondió con código HTTP ${resp.status}.`,
      });
      return { findings, riskContribution: 0 };
    }

    const raw = await resp.json();

    if (!raw.success) {
      findings.push({
        id: "geo-ip-unresolved",
        severity: "info",
        title: "IP no geolocalizada",
        description: raw.message || "No se encontraron registros de ubicación para la IP indicada.",
      });
      return { findings, riskContribution: 0 };
    }

    const geo: TechnicalEvidence["geolocation"] = {
      country: raw.country || "Desconocido",
      countryCode: raw.country_code || "XX",
      city: raw.city || "Desconocida",
      region: raw.region || "",
      lat: Number(raw.latitude) || 0,
      lon: Number(raw.longitude) || 0,
      asn: raw.connection?.asn ? `AS${raw.connection.asn} ${raw.connection.org || ""}`.trim() : "Desconocido",
      org: raw.connection?.org || raw.connection?.isp || "Desconocido",
      isp: raw.connection?.isp || "Desconocido",
    };

    const reverseDns = raw.connection?.domain ? String(raw.connection.domain) : undefined;

    // Análisis de riesgo sobre el ASN / ISP
    const orgLower = (geo.org + " " + geo.isp + " " + geo.asn).toLowerCase();

    // Detección de nodos de salida Tor conocidos o proxies
    if (orgLower.includes("tor exit") || orgLower.includes("zwiebelfreunde") || orgLower.includes("torservers")) {
      findings.push({
        id: "geo-tor-exit-node",
        severity: "high",
        title: "Nodo de Salida Tor (Tor Exit Relay)",
        description: "La dirección IP pertenece a un nodo de salida oficial de la red Tor. Suele emplearse para anonimizar tráfico y saltarse filtros perimetrales.",
        evidence: `ISP: ${geo.isp} | Org: ${geo.org}`,
      });
      riskScore += 35;
    } else if (orgLower.includes("bulletproof") || orgLower.includes("private layer") || orgLower.includes("cherry servers")) {
      findings.push({
        id: "geo-bulletproof-host",
        severity: "medium",
        title: "Proveedor de hosting catalogado como alto riesgo",
        description: `La IP pertenece a un ASN frecuentemente utilizado para alojar infraestructura de comando y control (C2) o phishing: ${geo.isp}.`,
        evidence: `ASN: ${geo.asn}`,
      });
      riskScore += 20;
    }

    // Información de infraestructura
    if (reverseDns) {
      findings.push({
        id: "geo-rdns-info",
        severity: "info",
        title: `Reverse DNS: ${reverseDns}`,
        description: `Nombre canónico asociado a la dirección IP ${cleanIp}.`,
      });
    }

    return {
      geolocation: geo,
      reverseDns,
      findings,
      riskContribution: riskScore,
    };
  } catch (err) {
    findings.push({
      id: "geo-error",
      severity: "info",
      title: "Geolocalización temporalmente no disponible",
      description: err instanceof Error ? err.message : "Error al conectar con ip-api.com",
    });
    return { findings, riskContribution: 0 };
  }
}
