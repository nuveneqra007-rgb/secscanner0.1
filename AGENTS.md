# ThreatScan / SecScanner

Herramienta web de análisis de amenazas: detecta anomalías en URLs, IPs, hashes y APKs/archivos y genera un reporte de riesgo (score 0-100, grado A-F, hallazgos por severidad).

## Stack
Next.js 16 (App Router) · React 19 · TypeScript 5 · Tailwind 4. Hosting: Vercel.

## Estructura
- `src/app/page.tsx`: orquesta input → escaneo → reporte + historial
- `src/lib/analyzer.ts`: motor de análisis (URL, IP, hash/APK). Archivo grande, leer solo la función necesaria
- `src/lib/types.ts`: contrato `ScanResult`, `Finding`, `TechnicalEvidence`. No romper sin avisar
- `src/lib/utils.ts`: detectIndicatorType, entropy, grade, verdict
- `src/lib/storage.ts`: historial en LocalStorage
- `src/components/`: ScannerInput, ScanningProgress, ThreatReport, HistoryPanel, RiskGauge

## Comandos
- `npm run dev` (puerto 3000) · `npm run build` · `npm run lint`
- Antes de dar una tarea por terminada: `npm run lint` y `npm run build` deben pasar.

## ESTADO REAL DEL PROYECTO (importante)
Hoy el análisis es **heurístico y simulado**: WHOIS, DNS, SSL, reputación de IP, VirusTotal, puertos, etc. se generan con `seededRandom` a partir del input. Nada de eso es dato real.

Reglas derivadas:
1. Nunca presentar datos simulados como reales. Todo dato simulado debe estar marcado como tal en la UI y en el JSON exportado.
2. El objetivo es reemplazar cada módulo simulado por una fuente real, de a uno, manteniendo el contrato `ScanResult`.
3. Mientras un módulo siga simulado, no inventar nombres de fuentes ni cifras que parezcan reales.

## Reglas de seguridad (es una herramienta de seguridad pública)
- Las API keys solo en el servidor (route handlers / variables de entorno). Nunca en el cliente ni en el repo.
- Si el servidor consulta una URL del usuario: bloquear SSRF (IPs privadas, localhost, metadata cloud, redirecciones a internas), con timeout y límite de tamaño.
- Archivos/APK: validar tipo y tamaño, no ejecutar nada, no guardar sin necesidad.
- Poner rate limiting a cualquier endpoint que consulte servicios externos.
- Validar y sanitizar todo input; no renderizar HTML del usuario.

## Convenciones de código
- TypeScript estricto, sin `any` salvo justificación en comentario.
- Funciones pequeñas y con un solo propósito; un archivo por tipo de indicador cuando se divida `analyzer.ts`.
- Textos de UI y mensajes al usuario en español.
- Commits pequeños y en imperativo (`feat:`, `fix:`, `refactor:`, `docs:`).
- No añadir dependencias nuevas sin explicar por qué y qué alternativa gratis existe.

## Forma de trabajar (ahorra tokens)
- Una tarea por sesión. Leer solo los archivos necesarios, no el repo completo.
- Primero un plan corto; implementar solo cuando se apruebe.
- Cambios mínimos: no reformatear ni reescribir archivos que no se tocan.

<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
