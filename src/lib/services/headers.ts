import { Finding, TechnicalEvidence } from "../types";
import { isSsrfTarget } from "../server/ssrf-guard";
import { safeRequest } from "../server/safe-request";

export interface HeadersServiceResult {
  headers: Record<string, string>;
  redirectChain: TechnicalEvidence["redirectChain"];
  findings: Finding[];
  riskContribution: number;
}

/**
 * Consulta cabeceras HTTP reales y audita la cadena de redirecciones mediante peticiones nativas seguras.
 */
export async function getHttpHeaders(targetUrl: string): Promise<HeadersServiceResult> {
  const findings: Finding[] = [];
  const redirectChain: NonNullable<TechnicalEvidence["redirectChain"]> = [];
  const headersRecord: Record<string, string> = {};
  let riskScore = 0;

  let currentUrl = targetUrl.trim();
  if (!/^https?:\/\//i.test(currentUrl)) {
    currentUrl = `https://${currentUrl}`;
  }

  const MAX_REDIRECTS = 5;
  let hops = 0;
  let finalHeaders: Record<string, string> | null = null;

  while (hops < MAX_REDIRECTS) {
    hops++;

    // Validación preventiva anti-SSRF en cada salto de redirección
    if (isSsrfTarget(currentUrl)) {
      findings.push({
        id: `redirect-ssrf-blocked-${hops}`,
        severity: "critical",
        title: "Redirección maliciosa hacia red interna bloqueada",
        description: `El servidor intentó redirigir hacia '${currentUrl}', un recurso privado o interno prohibido.`,
        evidence: `Salto #${hops}: ${currentUrl}`,
      });
      riskScore += 50;
      break;
    }

    try {
      let resp = await safeRequest(currentUrl, "HEAD");
      if (resp.status === 405 || resp.status === 501) {
        resp = await safeRequest(currentUrl, "GET");
      }

      finalHeaders = resp.headers;
      const isRedirect = [301, 302, 303, 307, 308].includes(resp.status);
      const location = resp.headers["location"];

      redirectChain.push({
        url: currentUrl,
        status: resp.status,
        location: location || undefined,
      });

      if (isRedirect && location) {
        try {
          const nextUrl = new URL(location, currentUrl).toString();

          // Comprobar si cambia de dominio en la redirección
          const origHost = new URL(currentUrl).hostname;
          const nextHost = new URL(nextUrl).hostname;

          if (origHost !== nextHost) {
            findings.push({
              id: `redirect-cross-domain-${hops}`,
              severity: "medium",
              title: "Redirección externa entre dominios distintos",
              description: `El sitio redirige desde '${origHost}' hacia '${nextHost}'. Patrón común en pasarelas de phishing y cloaking.`,
              evidence: `${currentUrl} (${resp.status}) -> ${nextUrl}`,
            });
            riskScore += 15;
          }

          currentUrl = nextUrl;
          continue;
        } catch {
          break;
        }
      }

      // Si no es redirección, llegamos al destino final
      break;
    } catch (err) {
      findings.push({
        id: `http-request-error-${hops}`,
        severity: "info",
        title: "Conexión HTTP finalizada",
        description: `No se pudo completar la petición hacia ${currentUrl}: ${err instanceof Error ? err.message : "Error de conexión"}`,
      });
      break;
    }
  }

  // Si hubo más de 3 saltos, advertir sobre cadena excesiva
  if (redirectChain.length > 3) {
    findings.push({
      id: "excessive-redirect-chain",
      severity: "high",
      title: "Cadena de redirecciones excesiva (Técnica de evasión)",
      description: `Se detectaron ${redirectChain.length} saltos sucesivos de redirección. Habitual en campañas maliciosas para agotar scrapers y ocultar el destino real.`,
    });
    riskScore += 25;
  }

  // Analizar cabeceras de seguridad del último salto
  if (finalHeaders) {
    Object.assign(headersRecord, finalHeaders);

    const isHttps = currentUrl.startsWith("https://");

    // 1. Strict-Transport-Security (HSTS)
    if (isHttps) {
      if (!headersRecord["strict-transport-security"]) {
        findings.push({
          id: "hdr-missing-hsts",
          severity: "medium",
          title: "Ausencia de cabecera HSTS (Strict-Transport-Security)",
          description: "El sitio no impone HTTPS forzado mediante HSTS, dejando a los usuarios expuestos a ataques de degradación SSL strip y MITM.",
        });
        riskScore += 10;
      }
    }

    // 2. Content-Security-Policy (CSP)
    if (!headersRecord["content-security-policy"]) {
      findings.push({
        id: "hdr-missing-csp",
        severity: "medium",
        title: "Ausencia de política de seguridad de contenido (CSP)",
        description: "No se define 'Content-Security-Policy'. El sitio carece de barreras del lado del navegador contra inyecciones XSS y cargas de scripts no autorizados.",
      });
      riskScore += 10;
    }

    // 3. X-Frame-Options
    if (!headersRecord["x-frame-options"] && !headersRecord["content-security-policy"]?.includes("frame-ancestors")) {
      findings.push({
        id: "hdr-missing-xfo",
        severity: "low",
        title: "Sin protección contra Clickjacking (X-Frame-Options)",
        description: "No se especifica 'X-Frame-Options: DENY|SAMEORIGIN'. La interfaz puede ser embebida en iframes invisibles para secuestro de clics.",
      });
      riskScore += 5;
    }

    // 4. X-Content-Type-Options
    if (headersRecord["x-content-type-options"]?.toLowerCase() !== "nosniff") {
      findings.push({
        id: "hdr-missing-nosniff",
        severity: "low",
        title: "Falta protección MIME Sniffing",
        description: "La cabecera 'X-Content-Type-Options: nosniff' no está presente o no es válida.",
      });
      riskScore += 5;
    }

    // 5. Exposición de software en cabeceras Server / X-Powered-By
    const serverHeader = headersRecord["server"];
    const poweredBy = headersRecord["x-powered-by"];

    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      findings.push({
        id: "hdr-server-leak",
        severity: "low",
        title: "Divulgación de versión de software en cabecera Server",
        description: `El servidor divulga su versión exacta ('${serverHeader}'), facilitando la búsqueda de exploits específicos a atacantes.`,
        evidence: `Server: ${serverHeader}`,
      });
      riskScore += 5;
    }

    if (poweredBy) {
      findings.push({
        id: "hdr-powered-by-leak",
        severity: "low",
        title: "Fuga de tecnología en X-Powered-By",
        description: `La cabecera expone la tecnología interna del backend ('${poweredBy}').`,
        evidence: `X-Powered-By: ${poweredBy}`,
      });
      riskScore += 5;
    }
  }

  return {
    headers: headersRecord,
    redirectChain,
    findings,
    riskContribution: riskScore,
  };
}
