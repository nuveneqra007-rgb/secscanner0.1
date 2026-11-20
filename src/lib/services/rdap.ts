import { Finding, TechnicalEvidence } from "../types";

export interface RdapServiceResult {
  whois?: TechnicalEvidence["whois"];
  findings: Finding[];
  riskContribution: number;
}

/**
 * Consulta el registro de dominio real mediante el protocolo estándar RDAP (sucesor JSON de WHOIS).
 */
export async function queryRdap(domain: string): Promise<RdapServiceResult> {
  const findings: Finding[] = [];
  let riskScore = 0;

  // Extraer dominio base (ej. "sub.example.com" -> "example.com")
  const parts = domain.trim().toLowerCase().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].split(".");
  const cleanDomain = parts.length >= 2 ? parts.slice(-2).join(".") : domain;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, {
      signal: controller.signal,
      headers: {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "SecScanner/0.1 (Threat Analyzer)",
      },
    });

    clearTimeout(timeout);

    if (resp.status === 404) {
      findings.push({
        id: "whois-not-found",
        severity: "medium",
        title: "Dominio no registrado o no indexado en RDAP",
        description: `El dominio '${cleanDomain}' no fue encontrado en los registros de su TLD. Podría estar disponible o en proceso de propagación.`,
      });
      return { findings, riskContribution: 15 };
    }

    if (!resp.ok) {
      findings.push({
        id: "whois-query-error",
        severity: "info",
        title: "Servicio RDAP no disponible para este TLD",
        description: `El servidor autoritativo de RDAP respondió con estado HTTP ${resp.status}.`,
      });
      return { findings, riskContribution: 0 };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await resp.json();

    // 1. Extraer Fechas (Eventos)
    const events: Array<{ eventAction: string; eventDate: string }> = Array.isArray(data.events) ? data.events : [];
    const getEventDate = (action: string): string | undefined => {
      const ev = events.find(e => e.eventAction?.toLowerCase() === action.toLowerCase());
      return ev?.eventDate ? new Date(ev.eventDate).toISOString() : undefined;
    };

    const created = getEventDate("registration");
    const expires = getEventDate("expiration");
    const updated = getEventDate("last changed") || getEventDate("last update of RDAP database");

    let ageDays: number | undefined = undefined;
    if (created) {
      const createdMs = new Date(created).getTime();
      ageDays = Math.max(0, Math.floor((Date.now() - createdMs) / (1000 * 60 * 60 * 24)));
    }

    // 2. Extraer Registrar y Contacto de Abuso de vcardArray
    let registrar = "Desconocido";
    let registrarAbuseContact: string | undefined = undefined;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const extractVcardProperty = (vcardArray: any, propName: string): string | undefined => {
      if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return undefined;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const prop = vcardArray[1].find((p: any) => Array.isArray(p) && p[0] === propName);
      return prop && prop[3] ? String(prop[3]) : undefined;
    };

    if (Array.isArray(data.entities)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const registrarEntity = data.entities.find((e: any) => Array.isArray(e.roles) && e.roles.includes("registrar"));
      if (registrarEntity) {
        registrar =
          extractVcardProperty(registrarEntity.vcardArray, "fn") ||
          extractVcardProperty(registrarEntity.vcardArray, "org") ||
          registrarEntity.handle ||
          "Registrar no divulgado";

        // Buscar sub-entidad de abuso
        if (Array.isArray(registrarEntity.entities)) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const abuseEntity = registrarEntity.entities.find((sub: any) => Array.isArray(sub.roles) && sub.roles.includes("abuse"));
          if (abuseEntity) {
            registrarAbuseContact = extractVcardProperty(abuseEntity.vcardArray, "email");
          }
        }
      }
    }

    // 3. Evaluar EPP Status Codes
    const statusCodes: string[] = Array.isArray(data.status) ? data.status.map((s: unknown) => String(s).toLowerCase()) : [];
    const isSuspended = statusCodes.some(s => s.includes("hold"));

    if (isSuspended) {
      findings.push({
        id: "whois-domain-suspended",
        severity: "critical",
        title: "Dominio suspendido administrativamente (clientHold / serverHold)",
        description: `El registrador o registry ha suspendido este dominio ('${statusCodes.filter(s => s.includes("hold")).join(", ")}'). Señal habitual de incautación por fraude, abuso o malware.`,
      });
      riskScore += 50;
    }

    // 4. Evaluar Antigüedad del Dominio
    if (ageDays !== undefined) {
      if (ageDays <= 7) {
        findings.push({
          id: "whois-very-recent-domain",
          severity: "critical",
          title: `Dominio registrado hace solo ${ageDays} día(s)`,
          description: `Creado el ${created}. Los dominios de menos de una semana de vida son los vectores predilectos para campañas inmediatas de phishing y robo de credenciales.`,
          evidence: `Fecha de registro: ${created} (${ageDays} días)`,
        });
        riskScore += 40;
      } else if (ageDays <= 30) {
        findings.push({
          id: "whois-young-domain",
          severity: "high",
          title: `Dominio de reciente creación (${ageDays} días de antigüedad)`,
          description: `El dominio tiene menos de un mes de vida (${created}). Se recomienda cautela antes de confiar operaciones sensibles.`,
        });
        riskScore += 25;
      } else if (ageDays <= 90) {
        findings.push({
          id: "whois-moderate-age",
          severity: "medium",
          title: `Dominio con menos de 90 días (${ageDays} días)`,
          description: `Antigüedad moderada. El dominio aún se encuentra en ventana de observación de reputación.`,
        });
        riskScore += 10;
      } else if (ageDays > 1095) {
        // Más de 3 años
        findings.push({
          id: "whois-established-domain",
          severity: "info",
          title: `Dominio establecido (${Math.floor(ageDays / 365)} años de antigüedad)`,
          description: `Registrado en ${created}. Cuenta con trayectoria prolongada y baja probabilidad de ser una trampa descartable.`,
        });
      }
    }

    // 5. Registradores de Alto Riesgo
    const regLower = registrar.toLowerCase();
    const highRiskRegistrars = ["namecheap", "freenom", "hosting concepts", "porkbun", "tucows", "reg.ru"];
    if (highRiskRegistrars.some(r => regLower.includes(r)) && (ageDays === undefined || ageDays < 90)) {
      findings.push({
        id: "whois-budget-registrar",
        severity: "low",
        title: `Registrador frecuentemente asociado con campañas temporales (${registrar})`,
        description: `El registrador '${registrar}' es común en registros automatizados de bajo costo.`,
      });
      riskScore += 10;
    }

    const whois: TechnicalEvidence["whois"] = {
      registrar,
      created,
      expires,
      updated,
      ageDays,
      registrarAbuseContact,
    };

    return {
      whois,
      findings,
      riskContribution: riskScore,
    };
  } catch (err) {
    findings.push({
      id: "whois-error",
      severity: "info",
      title: "WHOIS / RDAP no disponible temporalmente",
      description: err instanceof Error ? err.message : "Error al consultar rdap.org",
    });
    return { findings, riskContribution: 0 };
  }
}
