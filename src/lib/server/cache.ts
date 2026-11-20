import crypto from "crypto";
import { ScanResult } from "../types";

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

export class LRUCache<T> {
  private cache = new Map<string, CacheEntry<T>>();
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(maxSize = 250, ttlMinutes = 30) {
    this.maxSize = maxSize;
    const envTtl = parseInt(process.env.CACHE_TTL_MINUTES || "", 10);
    this.ttlMs = (envTtl > 0 ? envTtl : ttlMinutes) * 60_000;
  }

  get(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (entry.expiresAt < Date.now()) {
      this.cache.delete(key);
      return null;
    }

    // LRU: Reordenar al final para marcarlo como recientemente accedido
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.data;
  }

  set(key: string, data: T): void {
    if (this.cache.size >= this.maxSize) {
      // Eliminar el elemento más antiguo (primer elemento del Map)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      data,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

/**
 * Instancia global de caché en memoria para reportes ScanResult.
 */
export const scanResultCache = new LRUCache<ScanResult>(300, 30);

/**
 * Genera una clave hash unívoca y normalizada para un indicador y tipo.
 */
export function generateCacheKey(indicator: string, type?: string, fileName?: string): string {
  const payload = `${indicator.trim().toLowerCase()}::${type || "auto"}::${fileName || ""}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}
