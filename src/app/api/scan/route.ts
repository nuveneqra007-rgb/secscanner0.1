import { NextResponse } from "next/server";
import { validateIndicator } from "@/lib/server/validator";
import { isSsrfTarget } from "@/lib/server/ssrf-guard";
import { checkRateLimit, getClientIp } from "@/lib/server/rate-limiter";
import { scanResultCache, generateCacheKey } from "@/lib/server/cache";
import { analyze } from "@/lib/analyzer/index";
import { IndicatorType } from "@/lib/types";

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

    // 4. Protección contra falsificación de peticiones del lado del servidor (SSRF Guard)
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

    // 6. Ejecución del análisis (Fase 0: Puente con motor analítico)
    const scanResult = analyze(sanitizedIndicator, fileName);

    // 7. Guardar en caché con TTL de 30 minutos
    scanResultCache.set(cacheKey, scanResult);

    // 8. Respuesta exitosa
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
