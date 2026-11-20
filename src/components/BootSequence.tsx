"use client";
import { useEffect, useState, useCallback, useTransition } from "react";
import Image from "next/image";

const BOOT_MESSAGES = [
  "> INITIALIZING SECSCANNER v0.1...",
  "> LOADING THREAT DATABASE...",
  "> CALIBRATING HEURISTIC ENGINE...",
  "> SYSTEM READY.",
];

export function BootSequence({ onComplete }: { onComplete: () => void }) {
  const [phase, setPhase] = useState<"boot" | "fadeout" | "done">(() => {
    if (typeof window !== "undefined") {
      try {
        if (sessionStorage.getItem("secscanner-booted")) {
          return "done";
        }
      } catch {
        /* noop */
      }
    }
    return "boot";
  });

  const [messageIndex, setMessageIndex] = useState(0);
  const [charCount, setCharCount] = useState(0);
  const [logoVisible, setLogoVisible] = useState(false);
  const [, startTransition] = useTransition();

  const finish = useCallback(() => {
    setPhase("fadeout");
    try {
      sessionStorage.setItem("secscanner-booted", "1");
    } catch {
      /* noop */
    }
    setTimeout(() => {
      setPhase("done");
      onComplete();
    }, 500);
  }, [onComplete]);

  // Si ya estaba en done al montar
  useEffect(() => {
    if (phase === "done") {
      onComplete();
    }
  }, [phase, onComplete]);

  // Mostrar logo
  useEffect(() => {
    if (phase !== "boot") return;
    const t = setTimeout(() => setLogoVisible(true), 150);
    return () => clearTimeout(t);
  }, [phase]);

  // Typewriter progresivo
  useEffect(() => {
    if (phase !== "boot") return;

    if (messageIndex >= BOOT_MESSAGES.length) {
      const t = setTimeout(finish, 500);
      return () => clearTimeout(t);
    }

    const currentMsg = BOOT_MESSAGES[messageIndex];
    if (charCount < currentMsg.length) {
      const charTimer = setTimeout(() => {
        setCharCount((prev) => prev + 1);
      }, 20);
      return () => clearTimeout(charTimer);
    }

    // Línea completa, pausar y pasar a la siguiente
    const nextLineTimer = setTimeout(() => {
      startTransition(() => {
        setMessageIndex((prev) => prev + 1);
        setCharCount(0);
      });
    }, 280);

    return () => clearTimeout(nextLineTimer);
  }, [messageIndex, charCount, phase, finish]);

  if (phase === "done") return null;

  const currentMsg = BOOT_MESSAGES[messageIndex] || "";
  const displayedLine = currentMsg.slice(0, charCount);

  return (
    <div
      onClick={finish}
      className={`fixed inset-0 z-[9999] bg-[#0A0A0A] flex flex-col items-center justify-center cursor-pointer select-none transition-opacity duration-500 ${
        phase === "fadeout" ? "opacity-0" : "opacity-100"
      }`}
    >
      {/* CRT texture */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "repeating-linear-gradient(0deg, transparent 0px, transparent 2px, rgba(255,255,255,0.02) 2px, rgba(255,255,255,0.02) 4px)",
        }}
      />

      {/* Scan sweep line */}
      <div
        className="absolute left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-white/40 to-transparent pointer-events-none"
        style={{ animation: "scanSweep 3s ease-in-out infinite" }}
      />

      {/* Logo con animación de entrada */}
      <div
        className={`mb-8 relative transition-all duration-700 ease-out ${
          logoVisible ? "opacity-100 scale-100" : "opacity-0 scale-95"
        }`}
      >
        <div className="relative p-4 rounded-2xl border border-[#333333] bg-[#121212] shadow-2xl flex items-center justify-center">
          <Image
            src="/logo.png"
            alt="SecScanner"
            width={140}
            height={140}
            className="object-contain filter contrast-125"
            priority
          />
          {/* Scanline sobre el logo */}
          <div
            className="absolute inset-0 rounded-xl pointer-events-none overflow-hidden"
            style={{
              background:
                "linear-gradient(180deg, transparent 0%, rgba(255,255,255,0.08) 50%, transparent 100%)",
              backgroundSize: "100% 8px",
            }}
          />
        </div>
      </div>

      {/* Terminal output */}
      <div className="font-mono text-xs text-[#A3A3A3] space-y-1.5 w-[320px] sm:w-[420px] px-4">
        {BOOT_MESSAGES.slice(0, messageIndex).map((msg, i) => (
          <div
            key={i}
            className={msg.includes("SYSTEM READY") ? "text-white font-bold tracking-wide" : "text-[#888888]"}
          >
            {msg}
          </div>
        ))}
        {messageIndex < BOOT_MESSAGES.length && (
          <div className="flex items-center text-white font-medium">
            <span>{displayedLine}</span>
            <span className="ml-0.5 animate-pulse text-[#E0E0E0] font-bold">▌</span>
          </div>
        )}
      </div>

      {/* Skip hint */}
      <div className="absolute bottom-8 text-[10px] font-mono text-[#555555] tracking-widest animate-pulse">
        [ CLICK O ESPACIO PARA SALTAR ]
      </div>
    </div>
  );
}
