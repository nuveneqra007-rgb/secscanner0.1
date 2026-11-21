import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Configuración Upstash Redis si las variables de entorno están presentes
let redisInstance: Redis | null = null;
let perIpLimiter: Ratelimit | null = null;
let globalLimiter: Ratelimit | null = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  try {
    redisInstance = Redis.fromEnv();
    perIpLimiter = new Ratelimit({
      redis: redisInstance,
      limiter: Ratelimit.slidingWindow(Number(process.env.RATE_LIMIT_MAX) || 10, "1 m"),
      prefix: "secscanner:ip",
    });
    globalLimiter = new Ratelimit({
      redis: redisInstance,
      limiter: Ratelimit.slidingWindow(200, "1 m"),
      prefix: "secscanner:global",
    });
  } catch (err) {
    console.warn("No se pudo inicializar Upstash Redis, utilizando rate limiting en memoria:", err);
    redisInstance = null;
  }
}

// Fallback in-memory rate limiting para entornos locales o despliegues sin Upstash configurado
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const memoryStore = new Map<string, RateLimitEntry>();
const WINDOW_MS = 60_000; // 1 minuto
const DEFAULT_MAX_REQUESTS = 10;

function checkMemoryRateLimit(ip: string) {
  const now = Date.now();
  const maxRequests = parseInt(process.env.RATE_LIMIT_MAX || "", 10) || DEFAULT_MAX_REQUESTS;

  if (memoryStore.size > 2000) {
    for (const [key, entry] of memoryStore.entries()) {
      if (entry.resetAt < now) memoryStore.delete(key);
    }
  }

  const existing = memoryStore.get(ip);
  if (!existing || existing.resetAt < now) {
    const resetAt = now + WINDOW_MS;
    memoryStore.set(ip, { count: 1, resetAt });
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

export async function checkRateLimit(ip: string): Promise<{
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}> {
  if (perIpLimiter && globalLimiter) {
    const [g, r] = await Promise.all([globalLimiter.limit("all"), perIpLimiter.limit(ip)]);
    const blocking = !g.success ? g : r;
    return {
      allowed: g.success && r.success,
      limit: r.limit,
      remaining: r.remaining,
      resetAt: blocking.reset,
      retryAfter: Math.max(1, Math.ceil((blocking.reset - Date.now()) / 1000)),
    };
  }

  return checkMemoryRateLimit(ip);
}

export function getClientIp(headers: Headers): string {
  return (
    headers.get("x-vercel-forwarded-for")?.split(",")[0].trim() ||
    headers.get("x-real-ip")?.trim() ||
    "unknown"
  );
}
