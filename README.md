# ThreatScan — Análisis de Amenazas

Herramienta web de **Threat Intelligence** para demostrar capacidad técnica en ciberseguridad. Análisis heurístico en tiempo real de URLs, IPs, hashes y APKs sin necesidad de registro, backend ni base de datos.

> **Resultados > Estética** — UI limpia, profesional y rápida, pensada para que un reclutador pegue un enlace y piense: *“este tipo sabe de seguridad”*.

![Stack](https://img.shields.io/badge/Next.js-16-black) ![TypeScript](https://img.shields.io/badge/TypeScript-5-blue) ![Tailwind](https://img.shields.io/badge/Tailwind-4-38bdf8)

---

## 🎯 Características

### Flujo Plug & Play (sin Login)
- **Input único central** que auto-detecta URL, IP, dominio, hash (MD5/SHA1/SHA256) o archivo APK.
- Drag & drop para APKs.
- Ejemplos clicables para probar sin escribir.

### Motor de Análisis (heurístico, realista)
**URLs**
- Typosquatting & Levenshtein distance vs marcas (PayPal, Google, Santander, etc.)
- Homoglyphs / Punycode (`xn--`)
- Acortadores (`bit.ly`, `t.co`…), truco `@`, IP en URL, HTTP sin TLS
- TLDs de alto riesgo (`.tk`, `.xyz`…), longitud sospechosa, abuso de subdominios, keywords de phishing, entropía/DGA, edad WHOIS, cabeceras faltantes

**IPs**
- Reputación AbuseIPDB / Spamhaus simulada, geolocalización + ASN, Tor Exit detection, puertos críticos (22, 3389, 445…), blocklists, PTR

**APKs / Hashes**
- Validación MD5/SHA1/SHA256, lookup simulado VirusTotal, extracción de permisos peligrosos (`SEND_SMS`, `READ_CONTACTS`, `SYSTEM_ALERT_WINDOW`…), firma debug, ofuscación, entropía, YARA

### Reporte de Amenazas (lo más importante)
- **Score de Riesgo 0–100** con gauge circular + **Grado A–F** + veredicto (Malicioso / Sospechoso / Limpio)
- Desglose por severidad: Crítico, Alto, Medio, Bajo, Info
- Explicaciones en lenguaje natural: *“El certificado SSL expiró hace 3 días”*, *“Dominio registrado hace 2 horas, típico de phishing”*
- Evidencia técnica: WHOIS, DNS, SSL, cabeceras HTTP, cadena de redirecciones, geolocalización, reputación, puertos, IOCs, permisos APK
- Recomendaciones accionables para SOC + aviso legal
- Acciones: copiar JSON, imprimir, nuevo escaneo

### Estados de carga detallados
```
Resolviendo DNS... → Verificando reputación... → Inspeccionando TLS/SSL → Heurística de phishing → Correlación MISP/OTX
```

### Persistencia local
- Historial de últimos **10 análisis** en `LocalStorage` (sin SQL).
- **Seed data**: 3 análisis precargados al primer inicio:
  1. `https://banc0-santander-secure-login.tk/...` — phishing bancario (F, 92 pts)
  2. `185.220.101.47` — Tor Exit con mala reputación (F, 88 pts)
  3. `https://github.com/trending` — URL limpia (A, 8 pts)

---

## 🚀 Inicio rápido

```bash
npm install
npm run dev      # http://localhost:3000
npm run build
npm start
```

No requiere variables de entorno, base de datos ni API keys — todo corre en cliente (heurística determinista con `seededRandom`).

---

## 🏗️ Arquitectura

```
src/
  app/
    page.tsx            # Orquestación: input → scanning → reporte + historial
    layout.tsx
    globals.css
  lib/
    analyzer.ts         # Motor heurístico (URLs, IPs, APKs) + seed data
    types.ts            # ScanResult, Finding, TechnicalEvidence
    storage.ts          # LocalStorage (10 últimos, 3 seed)
    utils.ts            # grade, verdict, detectIndicatorType, entropy...
  components/
    ScannerInput.tsx
    ScanningProgress.tsx
    ThreatReport.tsx
    HistoryPanel.tsx
    RiskGauge.tsx
```

- **Determinismo**: cada input genera el mismo reporte (hash → seeded RNG) para demos reproducibles.
- **Sin backend**: pensado para portafolio — si se quiere versión real, el contrato `ScanResult` está listo para conectar a VirusTotal / AbuseIPDB.

---

## 🎨 Diseño

- Dark SOC theme (`#09090b`, `zinc-900`), acentos cian/ámbar/rojo según riesgo.
- Tipografía sistema (sin dependencia de Google Fonts para build offline).
- Grid sutil + gradiente, sin animaciones excesivas.

---

## 📄 Licencia

MIT — Proyecto de portafolio.
