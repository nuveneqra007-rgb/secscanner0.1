"use client";

export function RiskGauge({ score, grade, verdict }: { score: number; grade: string; verdict: string }) {
  const pct = Math.max(2, Math.min(100, score));

  // Monocromático: rojo solo para riesgo alto, blanco/gris para el resto
  let color = "#E0E0E0";
  let bg = "rgba(224,224,224,0.1)";
  if (score >= 75) { color = "#FF3333"; bg = "rgba(255,51,51,0.12)"; }
  else if (score >= 40) { color = "#A3A3A3"; bg = "rgba(163,163,163,0.1)"; }

  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="relative flex flex-col items-center">
      <div className="relative w-[160px] h-[160px]">
        <svg width="160" height="160" className="transform -rotate-90">
          <circle cx="80" cy="80" r="54" stroke="rgba(255,255,255,0.06)" strokeWidth="10" fill="none" />
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
          <span className="text-[11px] tracking-[0.2em] text-[#666666] font-mono -mt-1">/ 100 RIESGO</span>
          <span
            className="mt-2 px-2.5 py-0.5 rounded-full text-xs font-bold tracking-widest border"
            style={{ background: bg, color, borderColor: color + "40" }}
          >
            GRADO {grade}
          </span>
        </div>
      </div>
      <div className={`mt-3 text-[11px] font-mono tracking-widest px-3 py-1 rounded-full border ${
        verdict === "malicious"
          ? "bg-[#FF3333]/10 text-[#FF3333] border-[#FF3333]/20"
          : verdict === "suspicious"
          ? "bg-[#A3A3A3]/10 text-[#A3A3A3] border-[#A3A3A3]/20"
          : "bg-[#E0E0E0]/10 text-[#E0E0E0] border-[#E0E0E0]/20"
      }`}>
        ● {verdict === "malicious" ? "MALICIOSO" : verdict === "suspicious" ? "SOSPECHOSO" : "LIMPIO"}
      </div>
    </div>
  );
}

export function RiskBar({ score }: { score: number }) {
  let color = "bg-[#E0E0E0]";
  if (score >= 75) color = "bg-[#FF3333]";
  else if (score >= 40) color = "bg-[#A3A3A3]";
  return (
    <div className="h-2 w-full bg-[#1A1A1A] rounded-full overflow-hidden">
      <div className={`h-full ${color} transition-all duration-700`} style={{ width: `${score}%` }} />
    </div>
  );
}
