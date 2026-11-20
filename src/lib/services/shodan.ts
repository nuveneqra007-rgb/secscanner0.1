import { Finding, Severity, TechnicalEvidence } from "../types";

export interface ShodanServiceResult {
  ports?: TechnicalEvidence["ports"];
  vulns: string[];
  cpes: string[];
  tags: string[];
  findings: Finding[];
  riskContribution: number;
}

const KNOWN_PORT_SERVICES: Record<number, { service: string; risk: Severity }> = {
  21:    { service: "FTP",            risk: "high" },
  22:    { service: "SSH",            risk: "medium" },
  23:    { service: "Telnet",         risk: "critical" },
  25:    { service: "SMTP",           risk: "medium" },
  53:    { service: "DNS",            risk: "low" },
  80:    { service: "HTTP",           risk: "low" },
  110:   { service: "POP3",           risk: "medium" },
  135:   { service: "RPC",            risk: "high" },
  139:   { service: "NetBIOS",        risk: "high" },
  143:   { service: "IMAP",           risk: "low" },
  443:   { service: "HTTPS",          risk: "low" },
  445:   { service: "SMB",            risk: "critical" },
  1433:  { service: "MS-SQL",         risk: "critical" },
  1521:  { service: "Oracle DB",      risk: "critical" },
  3306:  { service: "MySQL",          risk: "critical" },
  3389:  { service: "RDP",            risk: "critical" },
  5432:  { service: "PostgreSQL",     risk: "high" },
  5900:  { service: "VNC",            risk: "critical" },
  6379:  { service: "Redis",          risk: "critical" },
  8080:  { service: "HTTP-Proxy/Alt", risk: "low" },
  8443:  { service: "HTTPS-Alt",      risk: "low" },
  9200:  { service: "Elasticsearch",  risk: "critical" },
  27017: { service: "MongoDB",        risk: "critical" },
};

/**
 * Consulta puertos abiertos, CVEs y servicios expuestos vía Shodan InternetDB (Zero Auth, $0).
 */
export async function queryShodanInternetDb(ip: string): Promise<ShodanServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  const cleanIp = ip.trim().split(":")[0].replace(/^\[|\]$/g, "");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const resp = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(cleanIp)}`, {
      signal: controller.signal,
      headers: {
        "Accept": "application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (resp.status === 404) {
      // La IP no tiene puertos indexados ni expuestos
      return {
        ports: [],
        vulns: [],
        cpes: [],
        tags: [],
        findings: [
          {
            id: "shodan-no-open-ports",
            severity: "info",
            title: "Sin puertos públicos detectados en Shodan",
            description: "No se identificaron servicios expuestos de forma pasiva en la base de datos de InternetDB.",
          },
        ],
        riskContribution: 0,
      };
    }

    if (!resp.ok) {
      findings.push({
        id: "shodan-unavailable",
        severity: "info",
        title: "Shodan InternetDB no disponible",
        description: `El servicio respondió con código HTTP ${resp.status}.`,
      });
      return { vulns: [], cpes: [], tags: [], findings, riskContribution: 0 };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    const rawPorts: number[] = Array.isArray(data.ports) ? data.ports : [];
    const vulns: string[] = Array.isArray(data.vulns) ? data.vulns : [];
    const cpes: string[] = Array.isArray(data.cpes) ? data.cpes : [];
    const tags: string[] = Array.isArray(data.tags) ? data.tags : [];

    const ports: TechnicalEvidence["ports"] = rawPorts.map((port) => {
      const known = KNOWN_PORT_SERVICES[port];
      return {
        port,
        service: known ? known.service : `Puerto ${port}`,
        state: "open" as const,
        risk: known ? known.risk : "medium",
      };
    });

    // Detectar puertos de alto peligro expuestos
    const criticalPorts = ports.filter(p => p.risk === "critical");
    if (criticalPorts.length > 0) {
      const portNames = criticalPorts.map(p => `${p.port}/${p.service}`).join(", ");
      findings.push({
        id: "shodan-critical-ports",
        severity: "critical",
        title: `Servicios de alto riesgo expuestos a Internet (${criticalPorts.length})`,
        description: `Se detectaron puertos de bases de datos o administración remota accesibles sin filtrado perimetral: ${portNames}.`,
        evidence: `Puertos abiertos: ${portNames}`,
      });
      riskScore += 35;
    }

    // Detectar vulnerabilidades conocidas (CVEs)
    if (vulns.length > 0) {
      const cveList = vulns.slice(0, 8).join(", ");
      findings.push({
        id: "shodan-cves-detected",
        severity: "critical",
        title: `Vulnerabilidades CVE conocidas detectadas (${vulns.length})`,
        description: `Shodan reporta fallas de seguridad conocidas en este host: ${cveList}${vulns.length > 8 ? "..." : ""}.`,
        evidence: `CVEs: ${vulns.slice(0, 5).join(", ")}`,
      });
      riskScore += Math.min(45, vulns.length * 15);
    }

    // Alerta de superficie de ataque amplia
    if (rawPorts.length > 10) {
      findings.push({
        id: "shodan-wide-attack-surface",
        severity: "medium",
        title: `Superficie de ataque amplia (${rawPorts.length} puertos abiertos)`,
        description: "El host expone una cantidad inusualmente alta de servicios TCP a la red pública.",
      });
      riskScore += 15;
    } else if (rawPorts.length > 0 && criticalPorts.length === 0 && vulns.length === 0) {
      findings.push({
        id: "shodan-standard-ports",
        severity: "info",
        title: `Servicios estándar detectados (${rawPorts.length})`,
        description: `Puertos abiertos: ${rawPorts.join(", ")}.`,
      });
    }

    return {
      ports,
      vulns,
      cpes,
      tags,
      findings,
      riskContribution: riskScore,
    };
  } catch (err) {
    findings.push({
      id: "shodan-error",
      severity: "info",
      title: "Error al consultar Shodan InternetDB",
      description: err instanceof Error ? err.message : "Fallo de conexión",
    });
    return { vulns: [], cpes: [], tags: [], findings, riskContribution: 0 };
  }
}
