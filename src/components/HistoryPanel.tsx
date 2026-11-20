"use client";
import { ScanResult } from "@/lib/types";
import { formatDate } from "@/lib/utils";

// Mini barra de riesgo proporcional al score
function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 75 ? "bg-red-500"
    : score >= 40 ? "bg-amber-500"
    : score >= 20 ? "bg-sky-500"
    : "bg-emerald-500";
  return (
    <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden shrink-0">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
    </div>
  );
}

// Icono según tipo de indicador
function TypeIcon({ type }: { type: string }) {
  if (type === "url" || type === "domain") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
      </svg>
    );
  }
  if (type === "ip") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
      </svg>
    );
  }
  if (type === "hash" || type === "apk") {
    return (
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
      </svg>
    );
  }
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg>
  );
}

const VERDICT_STYLE = {
  malicious:  { dot: "bg-red-500",     badge: "bg-red-500/15 text-red-400 border-red-500/20",             label: "Malicioso" },
  suspicious: { dot: "bg-amber-500",   badge: "bg-amber-500/15 text-amber-400 border-amber-500/20",       label: "Sospechoso" },
  clean:      { dot: "bg-emerald-500", badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/20", label: "Limpio" },
  unknown:    { dot: "bg-zinc-500",    badge: "bg-zinc-800 text-zinc-400 border-zinc-700",                label: "Desconocido" },
} as const;

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
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 backdrop-blur overflow-hidden">
      {/* Cabecera */}
      <div className="px-5 py-3.5 flex items-center justify-between border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-bold tracking-widest text-zinc-300">HISTORIAL</h3>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-500">
            {history.length}/10
          </span>
        </div>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="text-[11px] font-mono text-zinc-600 hover:text-zinc-400 transition"
          >
            Limpiar todo
          </button>
        )}
      </div>

      {/* Estado vacío */}
      {history.length === 0 ? (
        <div className="py-10 px-6 flex flex-col items-center gap-3 text-center">
          <div className="w-10 h-10 rounded-xl bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-600">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
              <path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/>
            </svg>
          </div>
          <div>
            <div className="text-sm font-medium text-zinc-400">Sin escaneos aún</div>
            <div className="text-xs text-zinc-600 mt-0.5">Tus últimos 10 análisis aparecerán aquí</div>
          </div>
        </div>
      ) : (
        <div className="divide-y divide-zinc-800/60 max-h-[400px] overflow-y-auto">
          {history.map((item) => {
            const isSelected = item.id === selectedId;
            const vs = VERDICT_STYLE[item.verdict];

            return (
              <button
                key={item.id}
                onClick={() => onSelect(item)}
                className={`w-full text-left px-4 py-3.5 flex items-center gap-3 transition group
                  ${isSelected
                    ? "bg-zinc-800/80 border-l-2 border-l-cyan-500"
                    : "border-l-2 border-l-transparent hover:bg-zinc-800/40"}`}
              >
                {/* Icono de tipo */}
                <div className="w-8 h-8 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-500 shrink-0 group-hover:border-zinc-600 transition">
                  <TypeIcon type={item.type} />
                </div>

                {/* Info principal */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold tracking-wider px-2 py-0.5 rounded-full border ${vs.badge}`}>
                      {vs.label}
                    </span>
                    <span className="text-[11px] font-mono text-zinc-600">
                      {item.type.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-sm text-zinc-200 truncate">{item.normalizedInput}</div>
                  <div className="text-[11px] font-mono text-zinc-600 mt-0.5">
                    {formatDate(item.timestamp)}
                  </div>
                </div>

                {/* Score + barra */}
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  <span className={`text-sm font-black tabular-nums
                    ${item.riskScore >= 75 ? "text-red-400"
                    : item.riskScore >= 40 ? "text-amber-400"
                    : item.riskScore >= 20 ? "text-sky-400"
                    : "text-emerald-400"}`}>
                    {item.riskScore}
                  </span>
                  <ScoreBar score={item.riskScore} />
                  <span className="text-[10px] font-mono text-zinc-600">G: {item.grade}</span>
                </div>

                {/* Flecha */}
                <svg
                  width="13" height="13" viewBox="0 0 24 24" fill="none"
                  stroke="#52525b" strokeWidth="2"
                  className="shrink-0 group-hover:stroke-zinc-400 transition"
                >
                  <path d="M9 18l6-6-6-6"/>
                </svg>
              </button>
            );
          })}
        </div>
      )}

      {/* Footer */}
      <div className="px-4 py-2.5 bg-zinc-950/40 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-700">
        <span>LocalStorage · sin servidor</span>
        <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
      </div>
    </div>
  );
}
