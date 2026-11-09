"use client";
import { gradeFromScore } from "@/lib/utils";

export function RiskGauge({ score, grade, verdict }: { score: number; grade: string; verdict: string }) {
  const pct = Math.max(2, Math.min(100, score));
  // color by score
  let color = "#22c55e"; // green
  let bg = "rgba(34,197,94,0.15)";
  if (score >= 75) { color = "#ef4444"; bg = "rgba(239,68,68,0.15)"; }
  else if (score >= 40) { color = "#f59e0b"; bg = "rgba(245,158,11,0.15)"; }
  else if (score >= 20) { color = "#38bdf8"; bg = "rgba(56,189,248,0.15)"; }

  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="relative flex flex-col items-center">
      <div className="relative w-[160px] h-[160px]">
        <svg width="160" height="160" className="transform -rotate-90">
          <circle cx="80" cy="80" r="54" stroke="rgba(255,255,255,0.08)" strokeWidth="10" fill="none" />
          <circle
            cx="80" cy="80" r="54"
            stroke={color}
            strokeWidth="10"
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 1s ease-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[42px] font-black tracking-tighter leading-none" style={{ color }}>{score}</span>
          <span className="text-[11px] tracking-[0.2em] text-zinc-500 font-mono -mt-1">/ 100 RIESGO</span>
          <span className={`mt-2 px-2.5 py-0.5 rounded-full text-xs font-bold tracking-widest border`} style={{ background: bg, color, borderColor: color + "40" }}>
            GRADO {grade}
          </span>
        </div>
      </div>
      <div className={`mt-3 text-[11px] font-mono tracking-widest px-3 py-1 rounded-full border ${verdict==="malicious" ? "bg-red-500/10 text-red-400 border-red-500/20" : verdict==="suspicious" ? "bg-amber-500/10 text-amber-400 border-amber-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`}>
        ● {verdict==="malicious" ? "MALICIOSO" : verdict==="suspicious" ? "SOSPECHOSO" : "LIMPIO"}
      </div>
    </div>
  );
}

export function RiskBar({ score }: { score: number }) {
  let color = "bg-emerald-500";
  if (score >= 75) color = "bg-red-500";
  else if (score >= 40) color = "bg-amber-500";
  else if (score >= 20) color = "bg-sky-500";
  return (
    <div className="h-2 w-full bg-zinc-800 rounded-full overflow-hidden">
      <div className={`h-full ${color} transition-all duration-700`} style={{ width: `${score}%` }} />
    </div>
  );
}
