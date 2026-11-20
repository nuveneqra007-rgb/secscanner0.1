"use client";
import { ScanResult } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function HistoryPanel({ history, onSelect, onClear, selectedId }: { history: ScanResult[]; onSelect: (r: ScanResult)=>void; onClear: ()=>void; selectedId?: string }) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 backdrop-blur">
      <div className="p-5 flex items-center justify-between border-b border-zinc-800">
        <h3 className="text-xs font-bold tracking-[0.14em] text-zinc-300">HISTORIAL RECIENTE</h3>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-2 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-400">{history.length}/10</span>
          {history.length>0 && <button onClick={onClear} className="text-xs text-zinc-500 hover:text-zinc-300 underline underline-offset-4">Limpiar</button>}
        </div>
      </div>

      {history.length===0 ? (
        <div className="p-8 text-center">
          <div className="w-12 h-12 mx-auto rounded-xl bg-zinc-800 border border-zinc-700 flex items-center justify-center mb-3">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#71717a" strokeWidth="1.6"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          </div>
          <div className="text-sm text-zinc-400">Sin escaneos aún</div>
          <div className="text-xs text-zinc-600 mt-1">Tus últimos 10 análisis aparecerán aquí</div>
        </div>
      ) : (
        <div className="divide-y divide-zinc-800 max-h-[520px] overflow-auto">
          {history.map(item => {
            const isSelected = item.id===selectedId;
            const barColor = item.riskScore>=75 ? "bg-red-500" : item.riskScore>=40 ? "bg-amber-500" : item.riskScore>=20 ? "bg-sky-500" : "bg-emerald-500";
            const badge = item.verdict==="malicious" ? "bg-red-500 text-white" : item.verdict==="suspicious" ? "bg-amber-500 text-black" : "bg-emerald-500 text-white";
            return (
              <button
                key={item.id}
                onClick={()=> onSelect(item)}
                className={`w-full text-left p-4 flex gap-3 hover:bg-zinc-800/60 transition ${isSelected ? "bg-zinc-800 border-l-2 border-l-cyan-500" : "border-l-2 border-l-transparent"}`}
              >
                <div className={`mt-1 w-1 self-stretch rounded-full ${barColor}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold tracking-widest px-2 py-0.5 rounded-full ${badge}`}>{item.verdict==="malicious"?"MALICIOSO": item.verdict==="suspicious"?"SOSPECHOSO":"LIMPIO"}</span>
                    <span className="text-[11px] font-mono text-zinc-500">{item.riskScore} pts • Grado {item.grade}</span>
                  </div>
                  <div className="text-sm text-zinc-200 truncate pr-2">{item.normalizedInput}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-400">{item.type.toUpperCase()}</span>
                    <span className="text-[11px] font-mono text-zinc-500">{formatDate(item.timestamp)}</span>
                  </div>
                </div>
                <div className="shrink-0 self-center">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#52525b" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
                </div>
              </button>
            );
          })}
        </div>
      )}

      <div className="p-3 bg-zinc-950/50 border-t border-zinc-800 rounded-b-2xl flex items-center justify-between text-[11px] font-mono text-zinc-600">
        <span>Almacenado localmente (LocalStorage)</span>
        <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
      </div>
    </div>
  );
}
