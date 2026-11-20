import { promises as dns } from "dns";
import { Finding, TechnicalEvidence } from "../types";
import { isPrivateIp } from "../server/ssrf-guard";

export interface DnsServiceResult {
  records: TechnicalEvidence["dns"];
  reverseDns?: string;
  findings: Finding[];
  iocs: { type: string; value: string; context?: string }[];
  isRebindingAttack: boolean;
  resolvedIps: string[];
}

/**
 * Resuelve registros DNS reales (A, MX, TXT, NS, PTR) usando el módulo nativo de Node.js.
 */
export async function resolveDns(hostnameOrIp: string): Promise<DnsServiceResult> {
  const findings: Finding[] = [];
  const iocs: { type: string; value: string; context?: string }[] = [];
  const records: TechnicalEvidence["dns"] = {};
  let reverseDns: string | undefined = undefined;
  let isRebindingAttack = false;
  const resolvedIps: string[] = [];

  // Verificar si el input es una IP directa
  const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostnameOrIp);

  if (isDirectIp) {
    try {
      const ptrs = await Promise.race([
        dns.reverse(hostnameOrIp),
        new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error("Timeout PTR")), 4000)),
      ]);
      if (ptrs && ptrs.length > 0) {
        records.ptr = ptrs[0];
        reverseDns = ptrs[0];
        iocs.push({ type: "domain", value: ptrs[0], context: "Reverse DNS PTR" });
      }
    } catch {
      // Sin registro PTR asignado
    }

    return {
      records,
      reverseDns,
      findings,
      iocs,
      isRebindingAttack: false,
      resolvedIps: [hostnameOrIp],
    };
  }

  // Si es un hostname / dominio:
  const targetHost = hostnameOrIp.toLowerCase().trim();
  iocs.push({ type: "domain", value: targetHost, context: "Dominio analizado" });

  const queryWithTimeout = async <T>(promise: Promise<T>, timeoutMs = 4000): Promise<T | null> => {
    try {
      return await Promise.race([
        promise,
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error("DNS Timeout")), timeoutMs)),
      ]);
    } catch {
      return null;
    }
  };

  // Consultas paralelas a registros DNS
  const [aRecords, mxRecords, txtRecords, nsRecords] = await Promise.all([
    queryWithTimeout(dns.resolve4(targetHost)),
    queryWithTimeout(dns.resolveMx(targetHost)),
    queryWithTimeout(dns.resolveTxt(targetHost)),
    queryWithTimeout(dns.resolveNs(targetHost)),
  ]);

  // 1. Registros A (IPv4)
  if (aRecords && aRecords.length > 0) {
    records.a = aRecords;
    resolvedIps.push(...aRecords);

    for (const ip of aRecords) {
      // Detección de DNS Rebinding: el dominio público resuelve a IP privada interna
      if (isPrivateIp(ip)) {
        isRebindingAttack = true;
        findings.push({
          id: `dns-rebinding-${ip}`,
          severity: "critical",
          title: "Ataque potencial: DNS Rebinding / IP Interna",
          description: `El dominio '${targetHost}' resuelve a la dirección IP privada '${ip}', intentando alcanzar la red interna del servidor.`,
          evidence: `DNS A Record: ${ip}`,
        });
      }

      iocs.push({ type: "ipv4", value: ip, context: "Resolución DNS A" });
    }

    // Intentar reverse DNS para la primera IP
    try {
      const firstIp = aRecords[0];
      const ptrs = await queryWithTimeout(dns.reverse(firstIp), 2500);
      if (ptrs && ptrs.length > 0) {
        records.ptr = ptrs[0];
        reverseDns = ptrs[0];
      }
    } catch {
      // Ignorar fallo de PTR
    }
  } else {
    findings.push({
      id: "dns-no-a-records",
      severity: "medium",
      title: "Dominio sin registros A (IPv4)",
      description: `No se pudieron resolver direcciones IPv4 para '${targetHost}'. El dominio podría estar inactivo, configurado solo para IPv6 o suspendido.`,
    });
  }

  // 2. Registros MX (Mail Exchanger)
  if (mxRecords && mxRecords.length > 0) {
    const sortedMx = [...mxRecords].sort((a, b) => a.priority - b.priority);
    records.mx = sortedMx.map(mx => `${mx.exchange} (prioridad ${mx.priority})`);
    for (const mx of sortedMx) {
      iocs.push({ type: "domain", value: mx.exchange, context: `Servidor de correo MX (${mx.priority})` });
    }
  } else {
    findings.push({
      id: "dns-no-mx-records",
      severity: "info",
      title: "Sin registros de correo MX",
      description: `El dominio no tiene servidores de correo MX configurados. Si se hace pasar por una entidad financiera o comercial, esto es una anomalía frecuente en campañas de phishing.`,
    });
  }

  // 3. Registros TXT (SPF, DMARC, validaciones)
  if (txtRecords && txtRecords.length > 0) {
    // dns.resolveTxt devuelve un array de arrays de strings (chunks)
    const flattenedTxt = txtRecords.map(chunks => chunks.join(""));
    records.txt = flattenedTxt;

    const hasSpf = flattenedTxt.some(txt => txt.toLowerCase().startsWith("v=spf1"));
    if (hasSpf) {
      findings.push({
        id: "dns-spf-present",
        severity: "info",
        title: "Política SPF configurada",
        description: "El dominio cuenta con registro SPF para mitigar suplantación de identidad por correo.",
        evidence: flattenedTxt.find(txt => txt.toLowerCase().startsWith("v=spf1")),
      });
    } else {
      findings.push({
        id: "dns-spf-missing",
        severity: "low",
        title: "Sin política de autenticación SPF",
        description: "El dominio no define registro SPF (v=spf1), lo que facilita el spoofing de correos bajo este dominio.",
      });
    }
  } else {
    findings.push({
      id: "dns-no-txt",
      severity: "low",
      title: "Sin registros TXT",
      description: "No se identificaron registros TXT de verificación de propiedad ni políticas de seguridad de correo (SPF).",
    });
  }

  // 4. Registros NS (Nameservers)
  if (nsRecords && nsRecords.length > 0) {
    records.ns = nsRecords;
    for (const ns of nsRecords) {
      iocs.push({ type: "domain", value: ns, context: "Servidor de nombres NS" });
    }
  }

  return {
    records,
    reverseDns,
    findings,
    iocs,
    isRebindingAttack,
    resolvedIps,
  };
}
