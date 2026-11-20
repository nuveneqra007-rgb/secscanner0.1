interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const store = new Map<string, RateLimitEntry>();

const WINDOW_MS = 60_000; // 1 minuto
const DEFAULT_MAX_REQUESTS = 10;

/**
 * Control de tasa de peticiones (Rate Limiter) en memoria por dirección IP.
 */
export function checkRateLimit(clientIp: string): {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
} {
  const now = Date.now();
  const maxRequests = parseInt(process.env.RATE_LIMIT_MAX || "", 10) || DEFAULT_MAX_REQUESTS;

  // Limpieza preventiva si el mapa crece demasiado
  if (store.size > 2000) {
    for (const [key, entry] of store.entries()) {
      if (entry.resetAt < now) {
        store.delete(key);
      }
    }
  }

  const existing = store.get(clientIp);

  if (!existing || existing.resetAt < now) {
    const resetAt = now + WINDOW_MS;
    store.set(clientIp, { count: 1, resetAt });
    return {
      allowed: true,
      limit: maxRequests,
      remaining: maxRequests - 1,
      resetAt,
    };
  }

  if (existing.count >= maxRequests) {
    const retryAfter = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      resetAt: existing.resetAt,
      retryAfter,
    };
  }

  existing.count++;
  return {
    allowed: true,
    limit: maxRequests,
    remaining: maxRequests - existing.count,
    resetAt: existing.resetAt,
  };
}

/**
 * Extrae la IP pública del cliente a partir de las cabeceras HTTP de la petición.
 */
export function getClientIp(headers: Headers): string {
  const forwardedFor = headers.get("x-forwarded-for");
  if (forwardedFor) {
    // Tomar la primera IP de la lista de proxies
    const firstIp = forwardedFor.split(",")[0].trim();
    if (firstIp) return firstIp;
  }

  const realIp = headers.get("x-real-ip");
  if (realIp) return realIp.trim();

  const cfConnectingIp = headers.get("cf-connecting-ip");
  if (cfConnectingIp) return cfConnectingIp.trim();

  return "127.0.0.1";
}
