import http from "node:http";
import https from "node:https";
import { safeLookup } from "./ssrf-guard";

export function safeRequest(
  url: string,
  method: "HEAD" | "GET"
): Promise<{ status: number; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return reject(new Error("URL inválida"));
    }

    if (!["http:", "https:"].includes(u.protocol)) {
      return reject(new Error("Protocolo no permitido"));
    }
    if (u.port && !["80", "443"].includes(u.port)) {
      return reject(new Error("Puerto no permitido"));
    }

    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(
      u,
      {
        method,
        lookup: safeLookup,
        timeout: 4500,
        headers: { "User-Agent": "SecScanner/0.1 (Threat Analyzer)" },
      },
      (res) => {
        res.destroy(); // No se lee el cuerpo para mitigar ataques DoS
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
        }
        resolve({ status: res.statusCode ?? 0, headers });
      }
    );

    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}
