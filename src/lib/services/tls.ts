import tls from "tls";
import { Finding, TechnicalEvidence } from "../types";
import { safeLookup } from "../server/ssrf-guard";

export interface TlsServiceResult {
  ssl?: TechnicalEvidence["ssl"];
  findings: Finding[];
  riskContribution: number;
}

function certString(val: string | string[] | undefined): string {
  if (!val) return "";
  return Array.isArray(val) ? val.join(", ") : val;
}

/**
 * Inspecciona el certificado TLS/SSL real conectándose al puerto 443 del servidor.
 */
export async function getTlsCertificate(hostname: string, port = 443): Promise<TlsServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  return new Promise((resolve) => {
    let resolved = false;

    const finish = (result: TlsServiceResult) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    const cleanHost = hostname.trim().toLowerCase().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];

    const socket = tls.connect(
      {
        host: cleanHost,
        port,
        servername: cleanHost,
        lookup: safeLookup,
        rejectUnauthorized: false, // Permitir capturar certificados autofirmados o caducados para auditoría
        timeout: 5000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const isAuthorized = socket.authorized;
          const authError = socket.authorizationError;
          const authErrorMsg = authError ? String(authError.message || authError) : undefined;

          if (!cert || Object.keys(cert).length === 0) {
            findings.push({
              id: "ssl-no-cert",
              severity: "medium",
              title: "Sin certificado TLS/SSL expuesto",
              description: `El servidor en el puerto ${port} no entregó un certificado de clave pública.`,
            });
            socket.destroy();
            return finish({ findings, riskContribution: 20 });
          }

          // Parsear Subject Alternative Names (SANs)
          const sans: string[] = cert.subjectaltname
            ? cert.subjectaltname.split(",").map(s => s.trim().replace(/^DNS:/i, ""))
            : [];

          const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : undefined;
          const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : undefined;
          const expiryDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = new Date();

          const isExpired = expiryDate ? expiryDate < now : false;
          const daysUntilExpiry = expiryDate
            ? Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
            : undefined;

          const issuerOrg = certString(cert.issuer?.O) || certString(cert.issuer?.CN) || "Autoridad Desconocida";
          const subjectCN = certString(cert.subject?.CN) || cleanHost;

          // Detección de certificado caducado
          if (isExpired) {
            findings.push({
              id: "ssl-cert-expired",
              severity: "critical",
              title: "Certificado TLS/SSL caducado",
              description: `El certificado expiró el ${validTo}. Toda comunicación cifrada actual es insegura y genera advertencias de navegador.`,
              evidence: `Expiró: ${validTo}`,
            });
            riskScore += 45;
          } else if (daysUntilExpiry !== undefined && daysUntilExpiry <= 7) {
            findings.push({
              id: "ssl-cert-expiring-soon",
              severity: "high",
              title: "Certificado SSL próximo a expirar (< 7 días)",
              description: `El certificado actual caduca en ${daysUntilExpiry} día(s). Riesgo inminente de interrupción o abandono de infraestructura.`,
            });
            riskScore += 25;
          } else if (daysUntilExpiry !== undefined && daysUntilExpiry <= 30) {
            findings.push({
              id: "ssl-cert-expiring-month",
              severity: "medium",
              title: "Certificado SSL caduca en menos de 30 días",
              description: `Válido hasta ${validTo} (${daysUntilExpiry} días restantes).`,
            });
            riskScore += 10;
          }

          // Detección de Autofirmado (Self-Signed)
          const isSelfSigned =
            Boolean(authErrorMsg?.includes("SELF_SIGNED")) ||
            Boolean(cert.issuer?.CN && certString(cert.issuer.CN) === certString(cert.subject?.CN));

          if (isSelfSigned) {
            findings.push({
              id: "ssl-self-signed",
              severity: "critical",
              title: "Certificado TLS autofirmado (No confiable)",
              description: "El certificado no fue emitido por una Autoridad de Certificación reconocida en la cadena de confianza global.",
              evidence: `Issuer: ${issuerOrg} == Subject: ${subjectCN}`,
            });
            riskScore += 50;
          } else if (!isAuthorized && authErrorMsg) {
            findings.push({
              id: "ssl-unauthorized",
              severity: "high",
              title: `Cadena de certificación no verificada: ${authErrorMsg}`,
              description: "El sistema no pudo validar la cadena completa de certificados raíz.",
            });
            riskScore += 30;
          }

          // Verificación de cobertura del Hostname en los SANs o CN
          const matchesHost =
            subjectCN.toLowerCase() === cleanHost ||
            sans.some(san => {
              const lowerSan = san.toLowerCase();
              if (lowerSan === cleanHost) return true;
              if (lowerSan.startsWith("*.")) {
                const rootDomain = lowerSan.slice(2);
                return cleanHost.endsWith(rootDomain) && cleanHost.split(".").length === rootDomain.split(".").length + 1;
              }
              return false;
            });

          if (!matchesHost) {
            findings.push({
              id: "ssl-hostname-mismatch",
              severity: "high",
              title: "Incongruencia de Hostname en el Certificado (Name Mismatch)",
              description: `El nombre '${cleanHost}' no figura en los dominios cubiertos por el certificado (Subject: ${subjectCN}). Señal frecuente de infraestructura reutilizada o proxies de intercepción.`,
              evidence: `SANs: ${sans.slice(0, 5).join(", ")}${sans.length > 5 ? "..." : ""}`,
            });
            riskScore += 35;
          }

          // Información sobre el emisor
          if (issuerOrg.toLowerCase().includes("let's encrypt") || issuerOrg.toLowerCase().includes("zerossl")) {
            findings.push({
              id: "ssl-dv-cert",
              severity: "info",
              title: `Certificado DV automatizado (${issuerOrg})`,
              description: "Emisión de validación de dominio rápida sin verificación de entidad corporativa.",
            });
          }

          const sslEvidence: TechnicalEvidence["ssl"] = {
            issuer: issuerOrg,
            subject: subjectCN,
            validFrom,
            validTo,
            expired: isExpired,
            daysUntilExpiry,
            sans,
          };

          socket.destroy();
          return finish({
            ssl: sslEvidence,
            findings,
            riskContribution: riskScore,
          });
        } catch (err) {
          socket.destroy();
          findings.push({
            id: "ssl-inspection-error",
            severity: "info",
            title: "Inspección SSL parcial",
            description: `No se pudo parsear el certificado: ${err instanceof Error ? err.message : "Error desconocido"}`,
          });
          return finish({ findings, riskContribution: 0 });
        }
      }
    );

    socket.on("error", (err) => {
      socket.destroy();
      findings.push({
        id: "ssl-connection-failed",
        severity: "info",
        title: "Puerto 443 (HTTPS) no responde",
        description: `No se estableció conexión TLS en el puerto 443: ${err.message}`,
      });
      return finish({ findings, riskContribution: 0 });
    });

    socket.on("timeout", () => {
      socket.destroy();
      findings.push({
        id: "ssl-timeout",
        severity: "info",
        title: "Tiempo de espera agotado en TLS (Timeout)",
        description: "El servidor no respondió a la negociación TLS en 5 segundos.",
      });
      return finish({ findings, riskContribution: 0 });
    });
  });
}
