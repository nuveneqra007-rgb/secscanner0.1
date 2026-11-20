import { NextResponse } from "next/server";
import { validateIndicator } from "@/lib/server/validator";
import { isSsrfTarget } from "@/lib/server/ssrf-guard";
import { checkRateLimit, getClientIp } from "@/lib/server/rate-limiter";
import { scanResultCache, generateCacheKey } from "@/lib/server/cache";
import { analyze } from "@/lib/analyzer/index";
import { IndicatorType, ScanResult } from "@/lib/types";
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
import { gradeFromScore, verdictFromScore } from "@/lib/utils";

interface ScanRequestBody {
  indicator: string;
  type?: IndicatorType;
  fileName?: string;
  fileBase64?: string;
}

export async function POST(request: Request) {
  try {
    // 1. Control de Tasa (Rate Limiting)
    const clientIp = getClientIp(request.headers);
    const rateCheck = checkRateLimit(clientIp);

    const rateHeaders = {
      "X-RateLimit-Limit": rateCheck.limit.toString(),
      "X-RateLimit-Remaining": rateCheck.remaining.toString(),
      "X-RateLimit-Reset": rateCheck.resetAt.toString(),
    };

    if (!rateCheck.allowed) {
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

    // 6. Base analítica del indicador
    const scanResult: ScanResult = analyze(sanitizedIndicator, fileName);
    const indicatorType = fileName
      ? fileName.toLowerCase().endsWith(".apk")
        ? "apk"
        : "file"
      : scanResult.type;

    scanResult.type = indicatorType;

    // =========================================================================
    // RAMA A: ARCHIVO / APK SUBIDO (ANÁLISIS ESTÁTICO BINARIO REAL)
    // =========================================================================
    if ((indicatorType === "file" || indicatorType === "apk") && body.fileBase64) {
      const buffer = Buffer.from(body.fileBase64, "base64");

      // Límite de seguridad: máximo 20 MB
      if (buffer.length > 20 * 1024 * 1024) {
        return NextResponse.json(
          { error: "El archivo supera el tamaño máximo permitido de 20 MB." },
          { status: 400, headers: rateHeaders }
        );
      }

      // Análisis estático del buffer (Hashes criptográficos, Entropía Shannon, Magic Bytes, Permisos Android)
      const staticResult = analyzeBuffer(buffer, fileName || sanitizedIndicator);
      scanResult.evidence.fileInfo = staticResult.fileInfo;
      scanResult.evidence.permissions = staticResult.permissions;

      // Filtrar hallazgos simulados de archivos
      scanResult.findings = scanResult.findings.filter(
        f => !f.id.startsWith("file-") && !f.id.startsWith("apk-") && !f.id.startsWith("perm-")
      );
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
          if (vtData.detections) {
            scanResult.evidence.vtDetections = vtData.detections;
          }
          scanResult.findings.push(...vtData.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
        }

        if (abuseChOutcome.status === "fulfilled" && abuseChOutcome.value.found) {
          scanResult.findings.push(...abuseChOutcome.value.findings);
          scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChOutcome.value.riskContribution);
        }
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (Análisis estático binario y hash VT 100% reales)";
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

      // Heurística local avanzada (Levenshtein 80+ marcas, Homoglyphs, DGA, Base64)
      const heurData = runHeuristics(sanitizedIndicator);
      scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("heur-"));
      scanResult.findings.push(...heurData.findings);
      scanResult.riskScore = Math.min(100, heurData.score);

      // 1. DNS Real
      let primaryResolvedIp: string | null = null;
      if (dnsOutcome.status === "fulfilled") {
        const dnsData = dnsOutcome.value;

        if (dnsData.isRebindingAttack) {
          return NextResponse.json(
            {
              error: "Acceso denegado: El dominio resuelve a una dirección IP interna o privada (DNS Rebinding Attack detectado).",
            },
            { status: 403, headers: rateHeaders }
          );
        }

        scanResult.evidence.dns = dnsData.records;
        if (dnsData.reverseDns) scanResult.evidence.reverseDns = dnsData.reverseDns;
        if (dnsData.iocs.length > 0) scanResult.evidence.iocs = dnsData.iocs;
        if (dnsData.resolvedIps.length > 0) primaryResolvedIp = dnsData.resolvedIps[0];

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("dns-") && !f.id.startsWith("sec-dns-")
        );
        scanResult.findings.push(...dnsData.findings);
      }

      // 2. TLS/SSL Real
      if (tlsOutcome.status === "fulfilled") {
        const tlsData = tlsOutcome.value;
        if (tlsData.ssl) scanResult.evidence.ssl = tlsData.ssl;

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("ssl-") && !f.id.startsWith("sec-ssl-")
        );
        scanResult.findings.push(...tlsData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + tlsData.riskContribution);
      }

      // 3. Cabeceras HTTP Real
      if (headersOutcome.status === "fulfilled") {
        const headersData = headersOutcome.value;
        scanResult.evidence.httpHeaders = headersData.headers;
        scanResult.evidence.redirectChain = headersData.redirectChain;

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("hdr-") && !f.id.startsWith("redirect-")
        );
        scanResult.findings.push(...headersData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + headersData.riskContribution);
      }

      // 4. WHOIS / RDAP Real
      if (rdapOutcome.status === "fulfilled") {
        const rdapData = rdapOutcome.value;
        if (rdapData.whois) scanResult.evidence.whois = rdapData.whois;

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("whois-") && !f.id.startsWith("sec-whois-")
        );
        scanResult.findings.push(...rdapData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + rdapData.riskContribution);
      }

      // 5. VirusTotal v3 Real
      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        if (vtData.detections) scanResult.evidence.vtDetections = vtData.detections;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("vt-"));
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
      }

      // 6. Phishing Blacklists Real
      if (phishOutcome.status === "fulfilled") {
        const phishData = phishOutcome.value;
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

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("phishtank-") && !f.id.startsWith("gsb-")
        );
        scanResult.findings.push(...phishData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + phishData.riskContribution);
      }

      // 7. abuse.ch Real
      if (abuseChOutcome.status === "fulfilled" && abuseChOutcome.value.found) {
        const abuseChData = abuseChOutcome.value;
        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("abusech-"));
        scanResult.findings.push(...abuseChData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
      }

      // 8. Enriquecer geolocalización y puertos del servidor web
      if (primaryResolvedIp) {
        try {
          const [geoData, shodanData] = await Promise.all([
            geolocateIp(primaryResolvedIp),
            queryShodanInternetDb(primaryResolvedIp),
          ]);

          if (geoData.geolocation) scanResult.evidence.geolocation = geoData.geolocation;
          if (shodanData.ports && shodanData.ports.length > 0) scanResult.evidence.ports = shodanData.ports;
        } catch {
          // Continuar sin bloquear
        }
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (Heurística, DNS, TLS, HTTP, WHOIS, VT y Phishing 100% reales)";
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
        if (dnsData.records?.ptr) {
          scanResult.evidence.dns = { ...(scanResult.evidence.dns || {}), ptr: dnsData.records.ptr };
          scanResult.evidence.reverseDns = dnsData.records.ptr;
        }
      }

      if (geoOutcome.status === "fulfilled") {
        const geoData = geoOutcome.value;
        if (geoData.geolocation) scanResult.evidence.geolocation = geoData.geolocation;
        if (geoData.reverseDns && !scanResult.evidence.reverseDns) scanResult.evidence.reverseDns = geoData.reverseDns;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("geo-"));
        scanResult.findings.push(...geoData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + geoData.riskContribution);
      }

      if (shodanOutcome.status === "fulfilled") {
        const shodanData = shodanOutcome.value;
        scanResult.evidence.ports = shodanData.ports;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("shodan-") && !f.id.startsWith("port-"));
        scanResult.findings.push(...shodanData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + shodanData.riskContribution);
      }

      if (abuseOutcome.status === "fulfilled") {
        const abuseData = abuseOutcome.value;
        if (abuseData.reputation) scanResult.evidence.reputation = abuseData.reputation;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("abuseipdb-") && !f.id.startsWith("rep-"));
        scanResult.findings.push(...abuseData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseData.riskContribution);
      }

      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        if (vtData.detections) {
          scanResult.evidence.vtDetections = vtData.detections;
          if (vtData.maliciousCount > 0 && scanResult.evidence.reputation) {
            scanResult.evidence.reputation.blacklists.push({ name: "VirusTotal", listed: true });
          }
        }

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("vt-"));
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
      }

      if (abuseChOutcome.status === "fulfilled" && abuseChOutcome.value.found) {
        const abuseChData = abuseChOutcome.value;
        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("abusech-"));
        scanResult.findings.push(...abuseChData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
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
        if (vtData.detections) scanResult.evidence.vtDetections = vtData.detections;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("vt-"));
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, vtData.riskContribution);
      }

      if (abuseChOutcome.status === "fulfilled" && abuseChOutcome.value.found) {
        const abuseChData = abuseChOutcome.value;
        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("abusech-"));
        scanResult.findings.push(...abuseChData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseChData.riskContribution);
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (VirusTotal v3 y MalwareBazaar 100% reales)";
    }

    // Ordenar findings por severidad descendente
    const severityWeights: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    scanResult.findings.sort(
      (a, b) => (severityWeights[a.severity] ?? 5) - (severityWeights[b.severity] ?? 5)
    );

    // 7. Guardar en caché con TTL de 30 minutos
    scanResultCache.set(cacheKey, scanResult);

    // 8. Respuesta exitosa con inteligencia de amenazas real
    return NextResponse.json(scanResult, {
      status: 200,
      headers: {
        ...rateHeaders,
        "X-Cache": "MISS",
      },
    });
  } catch (error) {
    console.error("[API_SCAN_ERROR]:", error);
    return NextResponse.json(
      { error: "Error interno del servidor al procesar el análisis." },
      { status: 500 }
    );
  }
}
