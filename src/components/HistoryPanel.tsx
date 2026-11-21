"use client";
import { useState } from "react";
import { ScanResult, Verdict, IndicatorType } from "@/lib/types";
import { formatDate } from "@/lib/utils";

// ── Helpers ───────────────────────────────────────────────────────────────────

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 75 ? "bg-[#FF3333]" : score >= 40 ? "bg-[#A3A3A3]" : "bg-[#E0E0E0]";
  return (
    <div className="w-16 h-1.5 bg-[#1A1A1A] rounded-full overflow-hidden shrink-0 border border-[#333333]/50">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
    </div>
  );
}

function TypeIcon({ type }: { type: string }) {
  if (type === "url" || type === "domain") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="12" cy="12" r="10" />
        <path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" />
      </svg>
    );
  }
  if (type === "ip") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <rect x="2" y="3" width="20" height="14" rx="2" />
        <path d="M8 21h8M12 17v4" />
      </svg>
    );
  }
  if (type === "hash" || type === "apk" || type === "file") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
      </svg>
    );
  }
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.35-4.35" />
    </svg>
  );
}

const VERDICT_STYLE: Record<Verdict, { dot: string; badge: string; label: string }> = {
  malicious: {
    dot: "bg-[#FF3333]",
    badge: "bg-[#FF3333]/15 text-[#FF3333] border-[#FF3333]/30",
    label: "Malicioso",
  },
  suspicious: {
    dot: "bg-[#A3A3A3]",
    badge: "bg-[#A3A3A3]/15 text-[#A3A3A3] border-[#A3A3A3]/30",
    label: "Sospechoso",
  },
  clean: {
    dot: "bg-[#E0E0E0]",
    badge: "bg-[#E0E0E0]/15 text-[#E0E0E0] border-[#E0E0E0]/30",
    label: "Limpio",
  },
  unknown: {
    dot: "bg-[#666666]",
    badge: "bg-[#1A1A1A] text-[#888888] border-[#333333]",
    label: "Desconocido",
  },
};

type FilterVerdict = "all" | Verdict;
type FilterType = "all" | IndicatorType;

// ── HistoryPanel ──────────────────────────────────────────────────────────────

export function HistoryPanel({
  history,
  onSelect,
  onClear,
  selectedId,
}: {
  history: ScanResult[];
  onSelect: (r: ScanResult) => void;
  onClear: () => void;
  selectedId?: string;
}) {
  const [filterVerdict, setFilterVerdict] = useState<FilterVerdict>("all");
  const [filterType, setFilterType] = useState<FilterType>("all");
  const [query, setQuery] = useState("");

  const filtered = history.filter((item) => {
    if (filterVerdict !== "all" && item.verdict !== filterVerdict) return false;
    if (filterType !== "all" && item.type !== filterType) return false;
    if (query.trim()) {
      const q = query.toLowerCase();
      if (!item.normalizedInput.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const presentTypes = Array.from(new Set(history.map((h) => h.type)));

  return (
    <div className="rounded-2xl border border-[#333333] bg-[#121212]/80 backdrop-blur overflow-hidden shadow-xl max-w-full box-border">
      {/* ── Cabecera ── */}
      <div className="px-4 py-3 flex items-center justify-between border-b border-[#333333]">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-bold tracking-widest text-white uppercase">HISTORIAL</h3>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[#1A1A1A] border border-[#333333] text-[#A3A3A3]">
            {history.length}/10
          </span>
        </div>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="text-[11px] font-mono text-[#666666] hover:text-[#A3A3A3] transition"
          >
            Limpiar todo
          </button>
        )}
      </div>

      {/* ── Filtros ── */}
      {history.length > 2 && (
        <div className="px-4 py-2.5 border-b border-[#333333]/60 space-y-2 bg-[#0E0E0E]">
          {/* Búsqueda */}
          <div className="relative">
            <svg
              width="13"
              height="13"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#666666] pointer-events-none"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Buscar en historial…"
              className="w-full pl-8 pr-3 h-8 rounded-lg bg-[#0A0A0A] border border-[#333333] text-xs text-white placeholder:text-[#555555] focus:outline-none focus:border-[#666666] transition"
            />
            {query && (
              <button
                onClick={() => setQuery("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#666666] hover:text-white"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>

          {/* Pills de veredicto */}
          <div className="flex gap-1.5 flex-wrap">
            {(["all", "malicious", "suspicious", "clean"] as FilterVerdict[]).map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`text-[10px] font-bold tracking-wider px-2.5 py-1 rounded-full border transition ${
                  filterVerdict === v
                    ? v === "malicious"
                      ? "bg-[#FF3333] text-white border-[#FF3333]"
                      : v === "suspicious"
                      ? "bg-[#A3A3A3] text-black border-[#A3A3A3]"
                      : v === "clean"
                      ? "bg-[#E0E0E0] text-black border-[#E0E0E0]"
                      : "bg-white text-black border-white"
                    : "bg-[#1A1A1A] text-[#666666] border-[#333333] hover:border-[#666666] hover:text-[#A3A3A3]"
                }`}
              >
                {v === "all" ? "Todos" : v === "malicious" ? "Malicioso" : v === "suspicious" ? "Sospechoso" : "Limpio"}
              </button>
            ))}
          </div>

          {/* Pills de tipo */}
          {presentTypes.length > 1 && (
            <div className="flex gap-1.5 flex-wrap">
              <button
                onClick={() => setFilterType("all")}
                className={`text-[10px] font-mono px-2.5 py-1 rounded-full border transition ${
                  filterType === "all"
                    ? "bg-white text-black border-white"
                    : "bg-[#1A1A1A] text-[#666666] border-[#333333] hover:border-[#666666]"
                }`}
              >
                Todos
              </button>
              {presentTypes.map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`text-[10px] font-mono px-2.5 py-1 rounded-full border transition ${
                    filterType === t
                      ? "bg-white text-black border-white"
                      : "bg-[#1A1A1A] text-[#666666] border-[#333333] hover:border-[#666666]"
                  }`}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Estado vacío ── */}
      {history.length === 0 ? (
        <div className="py-10 px-6 flex flex-col items-center gap-3 text-center">
          <div className="w-10 h-10 rounded-xl bg-[#1A1A1A] border border-[#333333] flex items-center justify-center text-[#666666]">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
              <path d="M12 8v4l3 3" />
              <circle cx="12" cy="12" r="10" />
            </svg>
          </div>
          <div>
            <div className="text-sm font-medium text-[#A3A3A3]">Sin escaneos aún</div>
            <div className="text-xs text-[#666666] mt-0.5">Tus últimos 10 análisis aparecerán aquí</div>
          </div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-8 text-center text-sm text-[#666666]">Sin resultados para ese filtro</div>
      ) : (
        <div className="divide-y divide-[#222222] max-h-[400px] overflow-y-auto">
          {filtered.map((item) => {
            const isSelected = item.id === selectedId;
            const vs = VERDICT_STYLE[item.verdict];

            return (
              <button
                key={item.id}
                onClick={() => onSelect(item)}
                className={`w-full text-left px-4 py-3.5 flex items-center gap-3 transition group ${
                  isSelected
                    ? "bg-[#1A1A1A] border-l-2 border-l-white"
                    : "border-l-2 border-l-transparent hover:bg-[#1A1A1A]/50"
                }`}
              >
                {/* Icono de tipo */}
                <div className="w-8 h-8 rounded-lg bg-[#1A1A1A] border border-[#333333] flex items-center justify-center text-[#888888] shrink-0 group-hover:border-[#666666] transition">
                  <TypeIcon type={item.type} />
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded-full border ${vs.badge}`}>
                      {vs.label}
                    </span>
                    <span className="text-[11px] font-mono text-[#666666]">{item.type.toUpperCase()}</span>
                    {item.id.startsWith("demo_") ? (
                      <span className="text-[10px] font-bold tracking-wider px-2 py-0.5 rounded-full border bg-white/10 text-white border-white/20">
                        DEMO
                      </span>
                    ) : (item.isLive || item.dataSource === "live") ? (
                      <span className="text-[10px] font-bold font-mono tracking-wider px-2 py-0.5 rounded-full border bg-emerald-950/70 text-emerald-400 border-emerald-500/40 flex items-center gap-1">
                        <span className="w-1 h-1 rounded-full bg-emerald-400 animate-pulse" />
                        EN VIVO
                      </span>
                    ) : null}
                  </div>
                  <div className="text-sm text-white truncate font-mono">{item.normalizedInput}</div>
                  <div className="text-[11px] font-mono text-[#666666] mt-0.5">{formatDate(item.timestamp)}</div>
                </div>

                {/* Score */}
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  <span
                    className={`text-sm font-black tabular-nums ${
                      item.riskScore >= 75
                        ? "text-[#FF3333]"
                        : item.riskScore >= 40
                        ? "text-[#A3A3A3]"
                        : "text-[#E0E0E0]"
                    }`}
                  >
                    {item.riskScore}
                  </span>
                  <ScoreBar score={item.riskScore} />
                  <span className="text-[10px] font-mono text-[#666666]">G: {item.grade}</span>
                </div>

                <svg
                  width="13"
                  height="13"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#555555"
                  strokeWidth="2"
                  className="shrink-0 group-hover:stroke-white transition"
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </button>
            );
          })}
        </div>
      )}

      {/* ── Footer ── */}
      <div className="px-4 py-2.5 bg-[#0A0A0A] border-t border-[#333333]/60 flex items-center justify-between text-[11px] font-mono text-[#666666]">
        <span>Historial guardado solo en este navegador</span>
        <span className="w-1.5 h-1.5 bg-[#E0E0E0] rounded-full animate-pulse" />
      </div>
    </div>
  );
}
