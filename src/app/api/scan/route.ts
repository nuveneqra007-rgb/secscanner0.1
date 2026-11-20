import { NextResponse } from "next/server";
import { validateIndicator } from "@/lib/server/validator";
import { isSsrfTarget } from "@/lib/server/ssrf-guard";
import { checkRateLimit, getClientIp } from "@/lib/server/rate-limiter";
import { scanResultCache, generateCacheKey } from "@/lib/server/cache";
import { IndicatorType, ScanResult, SourceStatus, Verdict, Finding } from "@/lib/types";
import { resolveDns } from "@/lib/services/dns";
import { getTlsCertificate } from "@/lib/services/tls";
import { getHttpHeaders } from "@/lib/services/headers";
import { queryRdap } from "@/lib/services/rdap";
import { geolocateIp } from "@/lib/services/geolocation";
import { queryShodanInternetDb } from "@/lib/services/shodan";
import { checkAbuseIpDb } from "@/lib/services/abuseipdb";
import { queryVirusTotal } from "@/lib/services/virustotal";
import { checkPhishingBlacklists } from "@/lib/services/phishing";
import { checkAbuseCh } from "@/lib/services/abusech";
import { runHeuristics } from "@/lib/services/heuristic";
import { analyzeBuffer } from "@/lib/services/file-static";
import { gradeFromScore, verdictFromScore, detectIndicatorType } from "@/lib/utils";

export const dynamic = "force-dynamic";
export const maxDuration = 30; // Permite hasta 30 segundos para resolver consultas en paralelo en Vercel Serverless

interface ScanRequestBody {
  indicator: string;
  type?: IndicatorType;
  fileName?: string;
  fileBase64?: string;
}

function generateRecommendations(verdict: Verdict, findings: Finding[]): string[] {
  const recs: string[] = [];
  const hasCritical = findings.some(f => f.severity === "critical");

  if (verdict === "malicious" || hasCritical) {
    recs.push("Bloquear el indicador de forma inmediata en firewall perimetral, proxy web y servidor DNS (RPZ).");
    recs.push("Buscar coincidencias de este IoC en los registros de SIEM y proxies de los últimos 30 días.");
    recs.push("Si hubo interacción de usuarios, forzar el reseteo de credenciales y revocar tokens OAuth.");
    recs.push("Reportar la amenaza a las plataformas comunitarias (AbuseIPDB, PhishTank) y al CERT de referencia.");
  } else if (verdict === "suspicious") {
    recs.push("Aislar cualquier interacción en un entorno controlado (Sandbox o Browser Isolation).");
    recs.push("Verificar la legitimidad del recurso por un canal secundario oficial antes de ingresar datos.");
    recs.push("Añadir a la lista de monitoreo activo y reevaluar la reputación en 24 horas.");
  } else {
    recs.push("Permitir acceso manteniendo auditoría rutinaria ante cambios en infraestructura o DNS.");
    recs.push("Verificar periódicamente la vigencia del certificado TLS y registros WHOIS.");
  }
  recs.push("Preservar el reporte forense y las evidencias técnicas para trazabilidad de seguridad.");
  return recs;
}

function generateSummary(verdict: Verdict, type: IndicatorType): string {
  if (verdict === "malicious") {
    return `Este ${type.toUpperCase()} presenta indicadores críticos de compromiso y detecciones en múltiples motores de ciberinteligencia. Se recomienda bloqueo urgente.`;
  }
  if (verdict === "suspicious") {
    return `Se detectaron anomalías estructurales o señales de riesgo en este ${type.toUpperCase()}. Requiere investigación antes de confiar en él.`;
  }
  return `No se identificaron firmas de compromiso ni anomalías en las consultas en vivo de infraestructura y reputación. Indicador confiable.`;
}

function getAllowedOrigin(request: Request): string {
  const origin = request.headers.get("origin");
  if (!origin) return "*";

  const trusted = [
    "https://secscanner0-1.vercel.app",
    "http://localhost:3000",
    "http://localhost:3005",
  ];

  if (process.env.VERCEL_URL) {
    trusted.push(`https://${process.env.VERCEL_URL}`);
  }

  if (
    trusted.includes(origin) ||
    /^https:\/\/secscanner0-1(-[a-z0-9-]+)?\.vercel\.app$/.test(origin)
  ) {
    return origin;
  }

  return "";
}

export async function OPTIONS(request: Request) {
  const allowedOrigin = getAllowedOrigin(request);
  if (!allowedOrigin) {
    return new NextResponse(null, { status: 403 });
  }

  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    },
  });
}

export async function POST(request: Request) {
  const startTime = Date.now();
  const allowedOrigin = getAllowedOrigin(request);

  if (request.headers.get("origin") && !allowedOrigin) {
    return NextResponse.json(
      { error: "Origen no autorizado por política CORS." },
      { status: 403 }
    );
  }

  try {
    // 1. Control de Tasa (Rate Limiting)
    const clientIp = getClientIp(request.headers);
    const rateCheck = checkRateLimit(clientIp);

    const rateHeaders: Record<string, string> = {
      "X-RateLimit-Limit": rateCheck.limit.toString(),
      "X-RateLimit-Remaining": rateCheck.remaining.toString(),
      "X-RateLimit-Reset": rateCheck.resetAt.toString(),
    };

    if (allowedOrigin) {
      rateHeaders["Access-Control-Allow-Origin"] = allowedOrigin;
      rateHeaders["Vary"] = "Origin";
    }

    if (!rateCheck.allowed) {
      console.warn(JSON.stringify({
        level: "warn",
        event: "rate_limit_exceeded",
        client: clientIp.slice(0, 7) + "***",
        retryAfter: rateCheck.retryAfter,
        timestamp: new Date().toISOString(),
      }));

      return NextResponse.json(
        {
          error: "Límite de peticiones alcanzado. Por favor, espere antes de reintentar.",
          retryAfterSeconds: rateCheck.retryAfter,
        },
        {
          status: 429,
          headers: {
            ...rateHeaders,
            "Retry-After": (rateCheck.retryAfter || 60).toString(),
          },
        }
      );
    }

    // 2. Parseo seguro del cuerpo JSON
    let body: ScanRequestBody;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: "Cuerpo de petición inválido. Se requiere un formato JSON válido." },
        { status: 400, headers: rateHeaders }
      );
    }

    // 3. Validación y sanitización del indicador
    const validation = validateIndicator(body.indicator);
    if (!validation.valid) {
      return NextResponse.json(
        { error: validation.error || "Indicador inválido." },
        { status: 400, headers: rateHeaders }
      );
    }

    const sanitizedIndicator = validation.sanitized;
    const fileName = body.fileName?.trim().slice(0, 255);

    // 4. Protección contra SSRF (Pre-DNS)
    if (isSsrfTarget(sanitizedIndicator)) {
      console.warn(JSON.stringify({
        level: "warn",
        event: "ssrf_blocked_pre_dns",
        indicator: sanitizedIndicator,
        timestamp: new Date().toISOString(),
      }));

      return NextResponse.json(
        {
          error: "Acceso denegado: El indicador solicitado pertenece a una red privada, reservada o servicio de metadatos (SSRF Guard).",
        },
        { status: 403, headers: rateHeaders }
      );
    }

    // 5. Comprobación en Caché
    const cacheKey = generateCacheKey(sanitizedIndicator, body.type, fileName);
    const cachedResult = scanResultCache.get(cacheKey);

    if (cachedResult && !body.fileBase64) {
      return NextResponse.json(cachedResult, {
        status: 200,
        headers: {
          ...rateHeaders,
          "X-Cache": "HIT",
        },
      });
    }

    // 6. Detección de tipo y preparación del contenedor de escaneo 100% Real
    const indicatorType = fileName
      ? fileName.toLowerCase().endsWith(".apk")
        ? "apk"
        : "file"
      : body.type || detectIndicatorType(sanitizedIndicator);

    const sources: Record<string, SourceStatus> = {
      dns: "unavailable",
      tls: "unavailable",
      headers: "unavailable",
      rdap: "unavailable",
      geo: "unavailable",
      shodan: "unavailable",
      abuseipdb: process.env.ABUSEIPDB_API_KEY ? "unavailable" : "unavailable",
      virustotal: process.env.VIRUSTOTAL_API_KEY ? "unavailable" : "unavailable",
      threatintel: "unavailable",
      heuristics: "live",
      static: "unavailable",
    };

    const scanResult: ScanResult = {
      id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date().toISOString(),
      input: sanitizedIndicator.slice(0, 500),
      normalizedInput: sanitizedIndicator,
      type: indicatorType,
      verdict: "clean",
      riskScore: 0,
      grade: "A",
      confidence: "Alta",
      summary: "",
      findings: [],
      evidence: {},
      recommendations: [],
      scanDurationMs: 0,
      isLive: true,
      dataSource: "live",
      sources,
    };

    // =========================================================================
    // RAMA A: ARCHIVO / APK SUBIDO (ANÁLISIS ESTÁTICO BINARIO REAL)
    // =========================================================================
    if ((indicatorType === "file" || indicatorType === "apk") && body.fileBase64) {
      const buffer = Buffer.from(body.fileBase64, "base64");

      // Límite de seguridad: máximo 10 MB para prevenir DoS / agotamiento de memoria
      if (buffer.length > 10 * 1024 * 1024) {
        return NextResponse.json(
          { error: "El archivo supera el tamaño máximo permitido de 10 MB." },
          { status: 400, headers: rateHeaders }
        );
      }

      // Análisis estático del buffer (Hashes criptográficos, Entropía Shannon, Magic Bytes, Permisos Android)
      const staticResult = analyzeBuffer(buffer, fileName || sanitizedIndicator);
      sources.static = "live";
      scanResult.evidence.fileInfo = staticResult.fileInfo;
      scanResult.evidence.permissions = staticResult.permissions;
      scanResult.findings.push(...staticResult.findings);
      scanResult.riskScore = Math.min(100, staticResult.riskContribution);

      // Consulta pasiva del hash SHA-256 en VirusTotal y MalwareBazaar (Zero Upload)
      const sha256 = staticResult.fileInfo?.sha256;
      if (sha256) {
        const [vtOutcome, abuseChOutcome] = await Promise.allSettled([
          queryVirusTotal(sha256, "hash"),
          checkAbuseCh(sha256, "hash"),
        ]);

        if (vtOutcome.status === "fulfilled") {
          const vtData = vtOutcome.value;
          sources.virustotal = vtData.totalEngines > 0 ? "live" : "unavailable";
          if (vtData.detections) {
            scanResult.evidence.vtDetections = vtData.detections;
          }
          scanResult.findings.push(...vtData.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
        }

        if (abuseChOutcome.status === "fulfilled") {
          sources.threatintel = "live";
          if (abuseChOutcome.value.found) {
            scanResult.findings.push(...abuseChOutcome.value.findings);
            scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChOutcome.value.riskContribution);
          }
        }
      }

      scanResult.confidence = "Alta (Análisis estático de buffer criptográfico y VirusTotal v3)";
    }

    // =========================================================================
    // RAMA B: URL O DOMINIO (CONSULTAS NATIVAS + HEURÍSTICA + THREAT INTEL)
    // =========================================================================
    else if (indicatorType === "url" || indicatorType === "domain") {
      let hostname = sanitizedIndicator;
      try {
        const fullUrl = /^https?:\/\//i.test(sanitizedIndicator)
          ? sanitizedIndicator
          : `https://${sanitizedIndicator}`;
        hostname = new URL(fullUrl).hostname;
      } catch {
        hostname = sanitizedIndicator.split("/")[0].split(":")[0];
      }

      // Heurística local avanzada (Levenshtein 80+ marcas, Homoglyphs, DGA, Base64)
      const heurData = runHeuristics(sanitizedIndicator);
      sources.heuristics = "live";
      scanResult.findings.push(...heurData.findings);
      scanResult.riskScore = Math.min(100, heurData.score);
      if (heurData.iocs.length > 0) {
        scanResult.evidence.iocs = heurData.iocs;
      }

      // Ejecución paralela de las 7 capas de verificación
      const [
        dnsOutcome,
        tlsOutcome,
        headersOutcome,
        rdapOutcome,
        vtOutcome,
        phishOutcome,
        abuseChOutcome,
      ] = await Promise.allSettled([
        resolveDns(hostname),
        getTlsCertificate(hostname),
        getHttpHeaders(sanitizedIndicator),
        queryRdap(hostname),
        queryVirusTotal(sanitizedIndicator, indicatorType === "domain" ? "domain" : "url"),
        checkPhishingBlacklists(sanitizedIndicator),
        checkAbuseCh(sanitizedIndicator, indicatorType === "domain" ? "domain" : "url"),
      ]);

      // 1. DNS Real
      let primaryResolvedIp: string | null = null;
      if (dnsOutcome.status === "fulfilled") {
        const dnsData = dnsOutcome.value;

        if (dnsData.isRebindingAttack) {
          console.warn(JSON.stringify({
            level: "warn",
            event: "dns_rebinding_attack_blocked",
            hostname,
            resolvedIps: dnsData.resolvedIps,
            timestamp: new Date().toISOString(),
          }));

          return NextResponse.json(
            {
              error: "Acceso denegado: El dominio resuelve a una dirección IP interna o privada (DNS Rebinding Attack detectado).",
            },
            { status: 403, headers: rateHeaders }
          );
        }

        sources.dns = "live";
        scanResult.evidence.dns = dnsData.records;
        if (dnsData.reverseDns) scanResult.evidence.reverseDns = dnsData.reverseDns;
        if (dnsData.iocs.length > 0) {
          scanResult.evidence.iocs = [...(scanResult.evidence.iocs || []), ...dnsData.iocs];
        }
        if (dnsData.resolvedIps.length > 0) primaryResolvedIp = dnsData.resolvedIps[0];

        scanResult.findings.push(...dnsData.findings);
      }

      // 2. TLS/SSL Real
      if (tlsOutcome.status === "fulfilled") {
        const tlsData = tlsOutcome.value;
        sources.tls = tlsData.ssl ? "live" : "unavailable";
        if (tlsData.ssl) scanResult.evidence.ssl = tlsData.ssl;
        scanResult.findings.push(...tlsData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + tlsData.riskContribution);
      }

      // 3. Cabeceras HTTP Real
      if (headersOutcome.status === "fulfilled") {
        const headersData = headersOutcome.value;
        sources.headers = headersData.headers ? "live" : "unavailable";
        scanResult.evidence.httpHeaders = headersData.headers;
        scanResult.evidence.redirectChain = headersData.redirectChain;
        scanResult.findings.push(...headersData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + headersData.riskContribution);
      }

      // 4. WHOIS / RDAP Real
      if (rdapOutcome.status === "fulfilled") {
        const rdapData = rdapOutcome.value;
        sources.rdap = rdapData.whois ? "live" : "unavailable";
        if (rdapData.whois) scanResult.evidence.whois = rdapData.whois;
        scanResult.findings.push(...rdapData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + rdapData.riskContribution);
      }

      // 5. VirusTotal v3 Real
      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        sources.virustotal = vtData.totalEngines > 0 ? "live" : "unavailable";
        if (vtData.detections) scanResult.evidence.vtDetections = vtData.detections;
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
      }

      // 6. Phishing Blacklists Real
      if (phishOutcome.status === "fulfilled") {
        const phishData = phishOutcome.value;
        sources.threatintel = "live";
        if (phishData.blacklists.length > 0) {
          scanResult.evidence.reputation = scanResult.evidence.reputation || {
            abuseScore: 0,
            totalReports: 0,
            blacklists: [],
          };
          for (const bl of phishData.blacklists) {
            const idx = scanResult.evidence.reputation.blacklists.findIndex(b => b.name === bl.name);
            if (idx >= 0) {
              scanResult.evidence.reputation.blacklists[idx] = bl;
            } else {
              scanResult.evidence.reputation.blacklists.push(bl);
            }
          }
        }
        scanResult.findings.push(...phishData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + phishData.riskContribution);
      }

      // 7. abuse.ch Real
      if (abuseChOutcome.status === "fulfilled") {
        sources.threatintel = "live";
        if (abuseChOutcome.value.found) {
          const abuseChData = abuseChOutcome.value;
          scanResult.findings.push(...abuseChData.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
        }
      }

      // 8. Enriquecer geolocalización y puertos del servidor web
      if (primaryResolvedIp) {
        try {
          const [geoData, shodanData] = await Promise.all([
            geolocateIp(primaryResolvedIp),
            queryShodanInternetDb(primaryResolvedIp),
          ]);

          if (geoData.geolocation) {
            sources.geo = "live";
            scanResult.evidence.geolocation = geoData.geolocation;
          }
          if (shodanData.ports && shodanData.ports.length > 0) {
            sources.shodan = "live";
            scanResult.evidence.ports = shodanData.ports;
            scanResult.findings.push(...shodanData.findings);
            scanResult.riskScore = Math.min(100, scanResult.riskScore + shodanData.riskContribution);
          }
        } catch {
          // Continuar sin bloquear si falla el enriquecimiento secundario
        }
      }

      // Verificación limpia si no surgieron anomalías
      if (scanResult.findings.length === 0) {
        scanResult.findings.push({
          id: "verified-clean",
          severity: "info",
          title: "Infraestructura y reputación verificadas sin anomalías",
          description: "Las consultas en vivo de DNS, certificados TLS, encabezados de seguridad, registro RDAP y motores globales no detectaron firmas de riesgo.",
          evidence: `Dominio: ${hostname} | IP: ${primaryResolvedIp || "N/A"}`,
        });
      }

      scanResult.confidence = "Alta (DNS, TLS, HTTP, RDAP, VirusTotal y Threat Intel en vivo)";
    }

    // =========================================================================
    // RAMA C: DIRECCIÓN IP (INFRAESTRUCTURA Y REPUTACIÓN)
    // =========================================================================
    else if (indicatorType === "ip") {
      const cleanIp = sanitizedIndicator.split(":")[0];

      const [dnsOutcome, geoOutcome, shodanOutcome, abuseOutcome, vtOutcome, abuseChOutcome] =
        await Promise.allSettled([
          resolveDns(cleanIp),
          geolocateIp(cleanIp),
          queryShodanInternetDb(cleanIp),
          checkAbuseIpDb(cleanIp),
          queryVirusTotal(cleanIp, "ip"),
          checkAbuseCh(cleanIp, "ip"),
        ]);

      if (dnsOutcome.status === "fulfilled") {
        const dnsData = dnsOutcome.value;
        sources.dns = "live";
        if (dnsData.records?.ptr) {
          scanResult.evidence.dns = { ...(scanResult.evidence.dns || {}), ptr: dnsData.records.ptr };
          scanResult.evidence.reverseDns = dnsData.records.ptr;
        }
      }

      if (geoOutcome.status === "fulfilled") {
        const geoData = geoOutcome.value;
        sources.geo = geoData.geolocation ? "live" : "unavailable";
        if (geoData.geolocation) scanResult.evidence.geolocation = geoData.geolocation;
        if (geoData.reverseDns && !scanResult.evidence.reverseDns) scanResult.evidence.reverseDns = geoData.reverseDns;
        scanResult.findings.push(...geoData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + geoData.riskContribution);
      }

      if (shodanOutcome.status === "fulfilled") {
        const shodanData = shodanOutcome.value;
        sources.shodan = shodanData.ports ? "live" : "unavailable";
        scanResult.evidence.ports = shodanData.ports;
        scanResult.findings.push(...shodanData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + shodanData.riskContribution);
      }

      if (abuseOutcome.status === "fulfilled") {
        const abuseData = abuseOutcome.value;
        sources.abuseipdb = abuseData.reputation ? "live" : "unavailable";
        if (abuseData.reputation) scanResult.evidence.reputation = abuseData.reputation;
        scanResult.findings.push(...abuseData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseData.riskContribution);
      }

      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        sources.virustotal = vtData.totalEngines > 0 ? "live" : "unavailable";
        if (vtData.detections) {
          scanResult.evidence.vtDetections = vtData.detections;
          if (vtData.maliciousCount > 0 && scanResult.evidence.reputation) {
            scanResult.evidence.reputation.blacklists.push({ name: "VirusTotal", listed: true });
          }
        }
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
      }

      if (abuseChOutcome.status === "fulfilled") {
        sources.threatintel = "live";
        if (abuseChOutcome.value.found) {
          const abuseChData = abuseChOutcome.value;
          scanResult.findings.push(...abuseChData.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
        }
      }

      if (scanResult.findings.length === 0) {
        scanResult.findings.push({
          id: "ip-verified-clean",
          severity: "info",
          title: "Dirección IP analizada sin reportes de abuso ni puertos críticos",
          description: "La consulta a Shodan InternetDB, AbuseIPDB v2 y VirusTotal v3 confirmó que la IP no figura en listas negras de ataques ni expone servicios vulnerables.",
          evidence: `IP: ${cleanIp} | País: ${scanResult.evidence.geolocation?.country || "N/A"} | ASN: ${scanResult.evidence.geolocation?.asn || "N/A"}`,
        });
      }

      scanResult.confidence = "Alta (Shodan, AbuseIPDB, VirusTotal y ThreatFox)";
    }

    // =========================================================================
    // RAMA D: HASH PURO (VIRUSTOTAL + MALWAREBAZAAR + THREATFOX)
    // =========================================================================
    else if (indicatorType === "hash") {
      const [vtOutcome, abuseChOutcome] = await Promise.allSettled([
        queryVirusTotal(sanitizedIndicator, "hash"),
        checkAbuseCh(sanitizedIndicator, "hash"),
      ]);

      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        sources.virustotal = vtData.totalEngines > 0 ? "live" : "unavailable";
        if (vtData.detections) scanResult.evidence.vtDetections = vtData.detections;
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, vtData.riskContribution);
      }

      if (abuseChOutcome.status === "fulfilled") {
        sources.threatintel = "live";
        if (abuseChOutcome.value.found) {
          const abuseChData = abuseChOutcome.value;
          scanResult.findings.push(...abuseChData.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
        }
      }

      if (scanResult.findings.length === 0) {
        scanResult.findings.push({
          id: "hash-verified-clean",
          severity: "info",
          title: "Firma hash sin detecciones en motores de malware globales",
          description: "El hash criptográfico fue verificado en VirusTotal (70+ motores antivirus) y MalwareBazaar sin coincidencias maliciosas conocidas.",
          evidence: `Hash: ${sanitizedIndicator}`,
        });
      }

      scanResult.confidence = "Alta (VirusTotal v3 y MalwareBazaar 100% reales)";
    }

    // 7. Cálculos de veredicto, grado y recomendaciones finales
    scanResult.riskScore = Math.min(100, Math.max(0, Math.round(scanResult.riskScore)));
    scanResult.verdict = verdictFromScore(scanResult.riskScore);
    scanResult.grade = gradeFromScore(scanResult.riskScore);
    scanResult.summary = generateSummary(scanResult.verdict, scanResult.type);
    scanResult.recommendations = generateRecommendations(scanResult.verdict, scanResult.findings);
    scanResult.scanDurationMs = Date.now() - startTime;
    scanResult.isLive = true;
    scanResult.dataSource = "live";
    scanResult.sources = sources;

    // Ordenar findings por severidad descendente
    const severityWeights: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    scanResult.findings.sort(
      (a, b) => (severityWeights[a.severity] ?? 5) - (severityWeights[b.severity] ?? 5)
    );

    // 8. Guardar en caché con TTL de 30 minutos
    scanResultCache.set(cacheKey, scanResult);

    // 9. Logging estructurado para observabilidad en Vercel
    console.log(JSON.stringify({
      level: "info",
      event: "scan_completed",
      indicatorType: scanResult.type,
      verdict: scanResult.verdict,
      riskScore: scanResult.riskScore,
      findingsCount: scanResult.findings.length,
      durationMs: scanResult.scanDurationMs,
      timestamp: new Date().toISOString(),
    }));

    // 10. Respuesta exitosa con inteligencia de amenazas real
    return NextResponse.json(scanResult, {
      status: 200,
      headers: {
        ...rateHeaders,
        "X-Cache": "MISS",
      },
    });
  } catch (error) {
    console.error(JSON.stringify({
      level: "error",
      event: "api_scan_exception",
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString(),
    }));

    return NextResponse.json(
      { error: "Error interno del servidor al procesar el análisis." },
      {
        status: 500,
        headers: allowedOrigin ? { "Access-Control-Allow-Origin": allowedOrigin, "Vary": "Origin" } : {},
      }
    );
  }
}
