export function cn(...classes: (string | boolean | undefined | null)[]) {
  return classes.filter(Boolean).join(" ");
}

export function gradeFromScore(score: number): string {
  if (score >= 90) return "F";
  if (score >= 75) return "E";
  if (score >= 60) return "D";
  if (score >= 40) return "C";
  if (score >= 20) return "B";
  return "A";
}

export function verdictFromScore(score: number): import("./types").Verdict {
  if (score >= 75) return "malicious";
  if (score >= 40) return "suspicious";
  if (score >= 15) return "clean";
  return "clean";
}

export function verdictLabel(v: string) {
  switch (v) {
    case "malicious": return "MALICIOSO";
    case "suspicious": return "SOSPECHOSO";
    case "clean": return "LIMPIO";
    default: return v.toUpperCase();
  }
}

export function severityLabel(s: string) {
  switch (s) {
    case "critical": return "CRÍTICO";
    case "high": return "ALTO";
    case "medium": return "MEDIO";
    case "low": return "BAJO";
    case "info": return "INFO";
    default: return s.toUpperCase();
  }
}

export function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString("es-ES", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

export function detectIndicatorType(input: string): import("./types").IndicatorType {
  const trimmed = input.trim();
  // hash detection
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return "hash";
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return "hash";
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return "hash";
  // IP v4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "ip";
  // IP:port or CIDR
  if (/^(\d{1,3}\.){3}\d{1,3}:\d+$/.test(trimmed)) return "ip";
  // file apk
  if (trimmed.toLowerCase().endsWith(".apk")) return "apk";
  // URL with protocol
  if (/^https?:\/\//i.test(trimmed)) return "url";
  // domain-like
  if (/^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(trimmed)) {
    // if contains slash, treat as URL
    if (trimmed.includes("/")) return "url";
    return "domain";
  }
  return "url";
}

export function hashString(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function seededRandom(seed: number) {
  return function () {
    seed = Math.imul(seed, 1664525) + 1013904223;
    return (seed >>> 0) / 4294967296;
  };
}

export function generateFakeHash(input: string, len: number) {
  const chars = "abcdef0123456789";
  const seed = hashString(input);
  const rnd = seededRandom(seed);
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(rnd() * chars.length)];
  return out;
}

export function entropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / str.length;
    e -= p * Math.log2(p);
  }
  return e;
}
