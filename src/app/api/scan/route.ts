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
import { gradeFromScore, verdictFromScore } from "@/lib/utils";

interface ScanRequestBody {
  indicator: string;
  type?: IndicatorType;
  fileName?: string;
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

    if (cachedResult) {
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
    const indicatorType = scanResult.type;

    // =========================================================================
    // FASE 1, 2 Y 3: VERIFICACIÓN REAL (DNS, TLS, HTTP, WHOIS, GEO, SHODAN, VT, ABUSEIPDB)
    // =========================================================================

    if (indicatorType === "url" || indicatorType === "domain") {
      let hostname = sanitizedIndicator;
      try {
        const fullUrl = /^https?:\/\//i.test(sanitizedIndicator)
          ? sanitizedIndicator
          : `https://${sanitizedIndicator}`;
        hostname = new URL(fullUrl).hostname;
      } catch {
        hostname = sanitizedIndicator.split("/")[0].split(":")[0];
      }

      // Consultas concurrentes (Fases 1, 2 y 3)
      const [dnsOutcome, tlsOutcome, headersOutcome, rdapOutcome, vtOutcome] = await Promise.allSettled([
        resolveDns(hostname),
        getTlsCertificate(hostname),
        getHttpHeaders(sanitizedIndicator),
        queryRdap(hostname),
        queryVirusTotal(sanitizedIndicator, indicatorType === "domain" ? "domain" : "url"),
      ]);

      // 1. Verificación DNS Real
      let primaryResolvedIp: string | null = null;
      if (dnsOutcome.status === "fulfilled") {
        const dnsData = dnsOutcome.value;

        // Post-DNS SSRF check (DNS Rebinding)
        if (dnsData.isRebindingAttack) {
          return NextResponse.json(
            {
              error: "Acceso denegado: El dominio resuelve a una dirección IP interna o privada (DNS Rebinding Attack detectado).",
            },
            { status: 403, headers: rateHeaders }
          );
        }

        scanResult.evidence.dns = dnsData.records;
        if (dnsData.reverseDns) {
          scanResult.evidence.reverseDns = dnsData.reverseDns;
        }
        if (dnsData.iocs.length > 0) {
          scanResult.evidence.iocs = dnsData.iocs;
        }
        if (dnsData.resolvedIps.length > 0) {
          primaryResolvedIp = dnsData.resolvedIps[0];
        }

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("dns-") && !f.id.startsWith("sec-dns-")
        );
        scanResult.findings.push(...dnsData.findings);
      }

      // 2. Verificación TLS/SSL Real
      if (tlsOutcome.status === "fulfilled") {
        const tlsData = tlsOutcome.value;
        if (tlsData.ssl) {
          scanResult.evidence.ssl = tlsData.ssl;
        }

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("ssl-") && !f.id.startsWith("sec-ssl-")
        );
        scanResult.findings.push(...tlsData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + tlsData.riskContribution);
      }

      // 3. Verificación de Cabeceras HTTP Real
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

      // 4. Verificación WHOIS / RDAP Real
      if (rdapOutcome.status === "fulfilled") {
        const rdapData = rdapOutcome.value;
        if (rdapData.whois) {
          scanResult.evidence.whois = rdapData.whois;
        }

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("whois-") && !f.id.startsWith("sec-whois-")
        );
        scanResult.findings.push(...rdapData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + rdapData.riskContribution);
      }

      // 5. Verificación VirusTotal v3 Real (Fase 3)
      if (vtOutcome.status === "fulfilled") {
        const vtData = vtOutcome.value;
        if (vtData.detections) {
          scanResult.evidence.vtDetections = vtData.detections;
        }

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("vt-")
        );
        scanResult.findings.push(...vtData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + vtData.riskContribution);
      }

      // 6. Enriquecer geolocalización y puertos del servidor de hosting
      if (primaryResolvedIp) {
        try {
          const [geoData, shodanData] = await Promise.all([
            geolocateIp(primaryResolvedIp),
            queryShodanInternetDb(primaryResolvedIp),
          ]);

          if (geoData.geolocation) {
            scanResult.evidence.geolocation = geoData.geolocation;
          }
          if (shodanData.ports && shodanData.ports.length > 0) {
            scanResult.evidence.ports = shodanData.ports;
          }
        } catch {
          // Continuar sin bloquear
        }
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (DNS, TLS, HTTP, WHOIS y VirusTotal reales)";
    } else if (indicatorType === "ip") {
      const cleanIp = sanitizedIndicator.split(":")[0];

      // Consultas concurrentes para IP (Fases 1, 2 y 3)
      const [dnsOutcome, geoOutcome, shodanOutcome, abuseOutcome, vtOutcome] = await Promise.allSettled([
        resolveDns(cleanIp),
        geolocateIp(cleanIp),
        queryShodanInternetDb(cleanIp),
        checkAbuseIpDb(cleanIp),
        queryVirusTotal(cleanIp, "ip"),
      ]);

      // 1. DNS PTR
      if (dnsOutcome.status === "fulfilled") {
        const dnsData = dnsOutcome.value;
        if (dnsData.records?.ptr) {
          scanResult.evidence.dns = {
            ...(scanResult.evidence.dns || {}),
            ptr: dnsData.records.ptr,
          };
          scanResult.evidence.reverseDns = dnsData.records.ptr;
        }
      }

      // 2. Geolocalización Real
      if (geoOutcome.status === "fulfilled") {
        const geoData = geoOutcome.value;
        if (geoData.geolocation) {
          scanResult.evidence.geolocation = geoData.geolocation;
        }
        if (geoData.reverseDns && !scanResult.evidence.reverseDns) {
          scanResult.evidence.reverseDns = geoData.reverseDns;
        }

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("geo-"));
        scanResult.findings.push(...geoData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + geoData.riskContribution);
      }

      // 3. Shodan InternetDB Real (Puertos y CVEs)
      if (shodanOutcome.status === "fulfilled") {
        const shodanData = shodanOutcome.value;
        scanResult.evidence.ports = shodanData.ports;

        scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("shodan-") && !f.id.startsWith("port-"));
        scanResult.findings.push(...shodanData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + shodanData.riskContribution);
      }

      // 4. AbuseIPDB Real (Reputación y Denuncias)
      if (abuseOutcome.status === "fulfilled") {
        const abuseData = abuseOutcome.value;
        if (abuseData.reputation) {
          scanResult.evidence.reputation = abuseData.reputation;
        }

        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("abuseipdb-") && !f.id.startsWith("rep-")
        );
        scanResult.findings.push(...abuseData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + abuseData.riskContribution);
      }

      // 5. VirusTotal IP Real
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

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (Shodan, AbuseIPDB y VirusTotal reales)";
    } else if (indicatorType === "hash") {
      // Consultas concurrentes para Hash (VirusTotal v3)
      const vtOutcome = await queryVirusTotal(sanitizedIndicator, "hash");

      if (vtOutcome.detections) {
        scanResult.evidence.vtDetections = vtOutcome.detections;
      }

      scanResult.findings = scanResult.findings.filter(f => !f.id.startsWith("vt-"));
      scanResult.findings.push(...vtOutcome.findings);
      scanResult.riskScore = Math.min(100, vtOutcome.riskContribution);

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (VirusTotal v3 100% verificado)";
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
