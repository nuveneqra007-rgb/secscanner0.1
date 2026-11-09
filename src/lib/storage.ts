import { ScanResult } from "./types";
import { getSeedScans } from "./analyzer";

const KEY = "threatscan_history_v2";
const MAX = 10;

export function loadHistory(): ScanResult[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) {
      const seed = getSeedScans();
      saveHistory(seed);
      return seed;
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      const seed = getSeedScans();
      saveHistory(seed);
      return seed;
    }
    return parsed as ScanResult[];
  } catch {
    const seed = getSeedScans();
    return seed;
  }
}

export function saveHistory(items: ScanResult[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(KEY, JSON.stringify(items.slice(0, MAX)));
  } catch {}
}

export function addScan(result: ScanResult) {
  const hist = loadHistory();
  const next = [result, ...hist.filter(h => h.id !== result.id)].slice(0, MAX);
  saveHistory(next);
  return next;
}

export function clearHistory() {
  if (typeof window === "undefined") return;
  localStorage.removeItem(KEY);
}
