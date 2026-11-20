import { Finding, TechnicalEvidence } from "../types";

export interface AbuseIpDbServiceResult {
  reputation?: TechnicalEvidence["reputation"];
  findings: Finding[];
  riskContribution: number;
  abuseScore: number;
}

/**
 * Consulta la reputación de IP e historial de denuncias en AbuseIPDB v2.
 */
export async function checkAbuseIpDb(ip: string): Promise<AbuseIpDbServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    findings.push({
      id: "abuseipdb-no-key",
      severity: "info",
      title: "AbuseIPDB no configurado",
      description: "Clave ABUSEIPDB_API_KEY no detectada en las variables de entorno.",
    });
    return { findings, riskContribution: 0, abuseScore: 0 };
  }

  const cleanIp = ip.trim().split(":")[0].replace(/^\[|\]$/g, "");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(cleanIp)}&maxAgeInDays=90&verbose`;

    const resp = await fetch(url, {
      signal: controller.signal,
      headers: {
        "Key": apiKey,
        "Accept": "application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (resp.status === 429) {
      findings.push({
        id: "abuseipdb-rate-limited",
        severity: "info",
        title: "Cuota de AbuseIPDB alcanzada (429)",
        description: "Se ha alcanzado el límite diario de consultas gratuitas de AbuseIPDB (1,000 checks/día).",
      });
      return { findings, riskContribution: 0, abuseScore: 0 };
    }

    if (!resp.ok) {
      findings.push({
        id: "abuseipdb-http-error",
        severity: "info",
        title: "Error de consulta en AbuseIPDB",
        description: `La API respondió con código HTTP ${resp.status}.`,
      });
      return { findings, riskContribution: 0, abuseScore: 0 };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json: any = await resp.json();
    const data = json.data;

    if (!data) {
      return { findings, riskContribution: 0, abuseScore: 0 };
    }

    const abuseScore = Number(data.abuseConfidenceScore) || 0;
    const totalReports = Number(data.totalReports) || 0;
    const lastReported = data.lastReportedAt ? String(data.lastReportedAt) : undefined;
    const isWhitelisted = Boolean(data.isWhitelisted);
    const isTor = Boolean(data.isTor);

    const reputation: TechnicalEvidence["reputation"] = {
      abuseScore,
      totalReports,
      lastReported,
      blacklists: [
        { name: "AbuseIPDB", listed: abuseScore > 20 },
      ],
    };

    // Evaluación de riesgos
    if (isTor) {
      findings.push({
        id: "abuseipdb-tor-node",
        severity: "high",
        title: "Nodo Tor confirmado en AbuseIPDB",
        description: "AbuseIPDB cataloga esta dirección IP como un nodo activo de la red anónima Tor.",
      });
      riskScore += 25;
    }

    if (abuseScore >= 75) {
      findings.push({
        id: "abuseipdb-critical-abuse",
        severity: "critical",
        title: `Alta probabilidad de actividad maliciosa (Score: ${abuseScore}%)`,
        description: `IP registrada en AbuseIPDB con un ${abuseScore}% de confianza de abuso basado en ${totalReports} reporte(s) en los últimos 90 días.`,
        evidence: `Abuse Score: ${abuseScore}% | Denuncias: ${totalReports}`,
      });
      riskScore += 50;
    } else if (abuseScore >= 25) {
      findings.push({
        id: "abuseipdb-moderate-abuse",
        severity: "high",
        title: `Reportes activos de incidentes (Score: ${abuseScore}%)`,
        description: `Se registran ${totalReports} denuncia(s) recientes por escaneo de puertos, ataques de fuerza bruta o spam.`,
        evidence: `Abuse Score: ${abuseScore}%`,
      });
      riskScore += 25;
    } else if (isWhitelisted) {
      findings.push({
        id: "abuseipdb-whitelisted",
        severity: "info",
        title: "IP en lista blanca global (AbuseIPDB)",
        description: "La dirección IP pertenece a infraestructura institucional verificada.",
      });
    } else if (abuseScore === 0) {
      findings.push({
        id: "abuseipdb-clean",
        severity: "info",
        title: "Reputación limpia en AbuseIPDB",
        description: "No se registran denuncias de ataques en los últimos 90 días (Score: 0%).",
      });
    }

    return {
      reputation,
      findings,
      riskContribution: riskScore,
      abuseScore,
    };
  } catch (err) {
    findings.push({
      id: "abuseipdb-fetch-error",
      severity: "info",
      title: "Error de conexión con AbuseIPDB",
      description: err instanceof Error ? err.message : "Fallo de red",
    });
    return { findings, riskContribution: 0, abuseScore: 0 };
  }
}
