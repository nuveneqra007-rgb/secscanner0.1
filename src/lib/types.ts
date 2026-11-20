export type IndicatorType = "url" | "ip" | "domain" | "hash" | "file" | "apk";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  mitre?: string;
  cwe?: string;
}

export interface TechnicalEvidence {
  dns?: {
    a?: string[];
    mx?: string[];
    txt?: string[];
    ns?: string[];
    ptr?: string;
  };
  httpHeaders?: Record<string, string>;
  whois?: {
    registrar?: string;
    created?: string;
    expires?: string;
    updated?: string;
    ageDays?: number;
    registrarAbuseContact?: string;
  };
  ssl?: {
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    expired?: boolean;
    daysUntilExpiry?: number;
    sans?: string[];
  };
  redirectChain?: { url: string; status: number; location?: string }[];
  geolocation?: {
    country: string;
    countryCode: string;
    city: string;
    region: string;
    lat: number;
    lon: number;
    asn: string;
    org: string;
    isp: string;
  };
  ports?: { port: number; service: string; state: "open" | "filtered" | "closed"; risk: Severity }[];
  reverseDns?: string;
  reputation?: {
    abuseScore: number;
    totalReports: number;
    lastReported?: string;
    blacklists: { name: string; listed: boolean }[];
  };
  fileInfo?: {
    name: string;
    size: string;
    type: string;
    md5: string;
    sha1: string;
    sha256: string;
    entropy?: number;
    magic?: string;
  };
  permissions?: {
    name: string;
    severity: Severity;
    description: string;
    requested: boolean;
  }[];
  iocs?: { type: string; value: string; context?: string }[];
  ssdeep?: string;
  vtDetections?: { engine: string; result: string }[];
}

export interface ScanResult {
  id: string;
  timestamp: string;
  input: string;
  normalizedInput: string;
  type: IndicatorType;
  verdict: Verdict;
  riskScore: number; // 0-100, higher = more malicious
  grade: string; // A-F
  confidence: string;
  summary: string;
  findings: Finding[];
  evidence: TechnicalEvidence;
  recommendations: string[];
  scanDurationMs: number;
}

export interface ScanStep {
  id: string;
  label: string;
  detail: string;
  status: "pending" | "running" | "done" | "error";
  duration?: number;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "bg-red-500 text-white border-red-500",
  high: "bg-orange-500 text-white border-orange-500",
  medium: "bg-amber-500 text-black border-amber-500",
  low: "bg-sky-500 text-white border-sky-500",
  info: "bg-zinc-700 text-zinc-300 border-zinc-700",
};

export const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  low: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  info: "bg-zinc-800 text-zinc-400 border-zinc-700",
};
