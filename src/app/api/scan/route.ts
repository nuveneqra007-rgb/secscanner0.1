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
    // FASE 1 & FASE 2: VERIFICACIÓN REAL (DNS, TLS, HTTP, WHOIS/RDAP, GEOLOC)
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

      // Consultas concurrentes sin API key (DNS, TLS, Headers, RDAP)
      const [dnsOutcome, tlsOutcome, headersOutcome, rdapOutcome] = await Promise.allSettled([
        resolveDns(hostname),
        getTlsCertificate(hostname),
        getHttpHeaders(sanitizedIndicator),
        queryRdap(hostname),
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

        // Filtrar hallazgos simulados de DNS e inyectar los reales
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

        // Filtrar hallazgos simulados de SSL e inyectar los reales
        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("ssl-") && !f.id.startsWith("sec-ssl-")
        );
        scanResult.findings.push(...tlsData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + tlsData.riskContribution);
      }

      // 3. Verificación de Cabeceras HTTP y Redirecciones Real
      if (headersOutcome.status === "fulfilled") {
        const headersData = headersOutcome.value;
        scanResult.evidence.httpHeaders = headersData.headers;
        scanResult.evidence.redirectChain = headersData.redirectChain;

        // Filtrar hallazgos simulados de cabeceras e inyectar los reales
        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("hdr-") && !f.id.startsWith("redirect-")
        );
        scanResult.findings.push(...headersData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + headersData.riskContribution);
      }

      // 4. Verificación WHOIS / RDAP Real (Fase 2)
      if (rdapOutcome.status === "fulfilled") {
        const rdapData = rdapOutcome.value;
        if (rdapData.whois) {
          scanResult.evidence.whois = rdapData.whois;
        }

        // Filtrar hallazgos simulados de WHOIS e inyectar los reales
        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("whois-") && !f.id.startsWith("sec-whois-")
        );
        scanResult.findings.push(...rdapData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + rdapData.riskContribution);
      }

      // 5. Enriquecer geolocalización real con la IP resuelta del dominio
      if (primaryResolvedIp) {
        try {
          const geoData = await geolocateIp(primaryResolvedIp);
          if (geoData.geolocation) {
            scanResult.evidence.geolocation = geoData.geolocation;
          }
        } catch {
          // No bloquear si la geolocalización externa no responde
        }
      }

      // Recalcular grado y veredicto con las puntuaciones de riesgo reales
      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (DNS, TLS, HTTP y WHOIS 100% reales)";
    } else if (indicatorType === "ip") {
      const cleanIp = sanitizedIndicator.split(":")[0];

      // Consultas concurrentes para IP: PTR DNS y Geolocalización real
      const [dnsOutcome, geoOutcome] = await Promise.allSettled([
        resolveDns(cleanIp),
        geolocateIp(cleanIp),
      ]);

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

      if (geoOutcome.status === "fulfilled") {
        const geoData = geoOutcome.value;
        if (geoData.geolocation) {
          scanResult.evidence.geolocation = geoData.geolocation;
        }
        if (geoData.reverseDns && !scanResult.evidence.reverseDns) {
          scanResult.evidence.reverseDns = geoData.reverseDns;
        }

        // Filtrar hallazgos simulados de geolocalización e inyectar los reales
        scanResult.findings = scanResult.findings.filter(
          f => !f.id.startsWith("geo-")
        );
        scanResult.findings.push(...geoData.findings);
        scanResult.riskScore = Math.min(100, scanResult.riskScore + geoData.riskContribution);
      }

      scanResult.verdict = verdictFromScore(scanResult.riskScore);
      scanResult.grade = gradeFromScore(scanResult.riskScore);
      scanResult.confidence = "Alta (Geolocalización y PTR 100% reales)";
    }

    // Ordenar findings por severidad descendente
    const severityWeights: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    scanResult.findings.sort(
      (a, b) => (severityWeights[a.severity] ?? 5) - (severityWeights[b.severity] ?? 5)
    );

    // 7. Guardar en caché con TTL de 30 minutos
    scanResultCache.set(cacheKey, scanResult);

    // 8. Respuesta exitosa con datos reales
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
