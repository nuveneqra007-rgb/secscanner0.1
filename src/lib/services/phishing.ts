import { Finding } from "../types";

export interface PhishingServiceResult {
  blacklists: { name: string; listed: boolean }[];
  isPhishing: boolean;
  threatType?: string;
  findings: Finding[];
  riskContribution: number;
}

/**
 * Consulta PhishTank (base de datos comunitaria de phishing) para una URL específica.
 */
async function checkPhishTank(url: string): Promise<{
  inDatabase: boolean;
  verified: boolean;
  valid: boolean;
  phishId?: number;
  phishUrl?: string;
} | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const bodyParams = new URLSearchParams({
      url: url.trim(),
      format: "json",
    });

    if (process.env.PHISHTANK_APP_KEY) {
      bodyParams.append("app_key", process.env.PHISHTANK_APP_KEY);
    }

    const resp = await fetch("https://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      body: bodyParams,
      signal: controller.signal,
      headers: {
        "User-Agent": "phishtank/secscanner-0.1 (Threat Analyzer)",
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    clearTimeout(timeout);

    if (resp.status === 509) {
      // Rate limited por PhishTank
      return null;
    }

    if (!resp.ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const json: any = await resp.json();
    const results = json.results;

    if (!results) return null;

    return {
      inDatabase: Boolean(results.in_database),
      verified: Boolean(results.verified),
      valid: Boolean(results.valid),
      phishId: results.phish_id ? Number(results.phish_id) : undefined,
      phishUrl: results.phish_detail_page || undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Consulta Google Safe Browsing Lookup API v4 para verificar malware o ingeniería social (phishing).
 */
async function checkGoogleSafeBrowsing(url: string): Promise<{
  matched: boolean;
  threatType?: string;
} | null> {
  const apiKey = process.env.GOOGLE_SAFEBROWSING_KEY;
  if (!apiKey) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const body = {
      client: {
        clientId: "secscanner",
        clientVersion: "0.1",
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url.trim() }],
      },
    };

    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      }
    );

    clearTimeout(timeout);

    if (!resp.ok) return null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    if (Array.isArray(data.matches) && data.matches.length > 0) {
      return {
        matched: true,
        threatType: data.matches[0].threatType || "THREAT_DETECTED",
      };
    }

    return { matched: false };
  } catch {
    return null;
  }
}

/**
 * Orquesta la verificación de la URL en listas negras de phishing (PhishTank y Google Safe Browsing).
 */
export async function checkPhishingBlacklists(url: string): Promise<PhishingServiceResult> {
  const findings: Finding[] = [];
  const blacklists: { name: string; listed: boolean }[] = [];
  let riskScore = 0;
  let isPhishing = false;
  let detectedThreat: string | undefined = undefined;

  const [ptOutcome, gsbOutcome] = await Promise.allSettled([
    checkPhishTank(url),
    checkGoogleSafeBrowsing(url),
  ]);

  // 1. Procesar PhishTank
  if (ptOutcome.status === "fulfilled" && ptOutcome.value) {
    const pt = ptOutcome.value;
    if (pt.inDatabase && pt.valid) {
      isPhishing = true;
      blacklists.push({ name: "PhishTank", listed: true });
      findings.push({
        id: "phishtank-active-phish",
        severity: "critical",
        title: "URL confirmada en lista negra de PhishTank",
        description: `La comunidad de PhishTank cataloga esta URL como phishing activo verificado (ID: ${pt.phishId || "N/A"}).`,
        evidence: pt.phishUrl ? `Ficha técnica: ${pt.phishUrl}` : undefined,
      });
      riskScore += 55;
    } else if (pt.inDatabase) {
      blacklists.push({ name: "PhishTank", listed: true });
      findings.push({
        id: "phishtank-historical",
        severity: "medium",
        title: "URL registrada previamente en PhishTank",
        description: "El enlace figura en la base de datos de PhishTank pero se encuentra inactivo o pendiente de validación.",
      });
      riskScore += 15;
    } else {
      blacklists.push({ name: "PhishTank", listed: false });
    }
  }

  // 2. Procesar Google Safe Browsing
  if (gsbOutcome.status === "fulfilled" && gsbOutcome.value) {
    const gsb = gsbOutcome.value;
    if (gsb.matched && gsb.threatType) {
      isPhishing = true;
      detectedThreat = gsb.threatType;
      blacklists.push({ name: "Google Safe Browsing", listed: true });

      const threatName =
        gsb.threatType === "SOCIAL_ENGINEERING"
          ? "Ingeniería Social / Phishing"
          : gsb.threatType === "MALWARE"
          ? "Distribución de Malware"
          : gsb.threatType;

      findings.push({
        id: "gsb-threat-detected",
        severity: "critical",
        title: `Bloqueado por Google Safe Browsing (${threatName})`,
        description: `Google ha emitido una advertencia global para este sitio por actividad clasificada como ${threatName}.`,
        evidence: `Tipo de amenaza: ${gsb.threatType}`,
      });
      riskScore += 60;
    } else {
      blacklists.push({ name: "Google Safe Browsing", listed: false });
      findings.push({
        id: "gsb-clean",
        severity: "info",
        title: "Limpio en Google Safe Browsing",
        description: "No se identificaron advertencias de malware ni suplantación de identidad en Google Safe Browsing.",
      });
    }
  }

  return {
    blacklists,
    isPhishing,
    threatType: detectedThreat,
    findings,
    riskContribution: riskScore,
  };
}
