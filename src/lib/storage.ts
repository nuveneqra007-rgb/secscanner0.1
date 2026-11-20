import { ScanResult } from "./types";
import { getSeedScans } from "./analyzer";

const KEY = "threatscan_history_v2";
const MAX = 10;

export function loadHistory(): ScanResult[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) {
      // Primera visita: cargar seed data
      const seed = getSeedScans();
      saveHistory(seed);
      return seed;
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Array vacío = el usuario limpió explícitamente → respetar esa decisión
    return parsed as ScanResult[];
  } catch {
    return [];
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
  // Guardar array vacío en lugar de borrar la clave,
  // así loadHistory sabe que el usuario limpió explícitamente
  saveHistory([]);
}
