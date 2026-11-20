import { Finding, TechnicalEvidence } from "../types";
import { entropy } from "../utils";

const TARGET_BRANDS = [
  // Tech & Cloud
  "google", "apple", "microsoft", "amazon", "facebook", "instagram", "netflix",
  "github", "linkedin", "whatsapp", "telegram", "twitter", "adobe", "zoom",
  "dropbox", "icloud", "chatgpt", "openai", "spotify", "tiktok", "steam",
  // Banca Global y España
  "paypal", "santander", "bbva", "caixabank", "caixa", "bankinter", "sabadell",
  "ing", "abanca", "unicaja", "openbank", "chase", "wellsfargo", "citibank",
  "bankofamerica", "hsbc", "barclays", "bnp",
  // Banca Latinoamérica
  "banamex", "bcp", "interbank", "scotiabank", "bancolombia", "davivienda",
  "nequi", "daviplata", "mercadopago", "itau", "bradesco", "nubank",
  "bancoestado", "bancodechile", "galicia", "macro", "bbvafrances",
  "banrural", "bancopichincha", "produbanco",
  // Criptomonedas & Wallets
  "binance", "coinbase", "kraken", "kucoin", "bybit", "metamask", "ledger",
  "trezor", "okx", "bitso", "blockchain", "trustwallet", "phantom",
  // Envíos & Operadores
  "dhl", "fedex", "ups", "usps", "correos", "movistar", "claro", "vodafone",
  "telcel", "tmobile", "att", "orange",
  // Comercio & Pagos
  "stripe", "square", "mercadolibre", "ebay", "aliexpress", "booking", "airbnb",
];

const SUSPICIOUS_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work",
  ".date", ".party", ".buzz", ".cam", ".rest", ".bar", ".zip", ".mov",
  ".phishing", ".link", ".stream", ".gdn", ".racing", ".kim", ".science",
  ".surf", ".monster", ".cc", ".icu", ".live",
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
  "shorturl.at", "buff.ly", "rebrand.ly", "tiny.cc", "rb.gy", "v.gd",
]);

const SENSITIVE_KEYWORDS = [
  "login", "verify", "verification", "account", "security", "secure", "banking",
  "signin", "update", "wallet", "recover", "authenticate", "confirm", "billing",
  "invoice", "password", "credential", "suspend", "unlock", "valida", "acceso",
];

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

export interface HeuristicServiceResult {
  score: number;
  findings: Finding[];
  iocs: NonNullable<TechnicalEvidence["iocs"]>;
}

/**
 * Motor heurístico avanzado de detección de phishing, suplantación de identidad (typosquatting),
 * dominios algorítmicos (DGA), homoglyphs y anomalías sintácticas en URLs.
 */
export function runHeuristics(input: string): HeuristicServiceResult {
  const findings: Finding[] = [];
  const iocs: NonNullable<TechnicalEvidence["iocs"]> = [];
  let score = 0;

  const raw = input.trim();
  let hostname = raw.toLowerCase();
  let pathname = "";
  let search = "";

  try {
    const parsed = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
    search = parsed.search.toLowerCase();
  } catch {
    hostname = raw.split("/")[0].split(":")[0].toLowerCase();
  }

  // 1. Detección de IP directa como Hostname (omisión de DNS)
  const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (isDirectIp) {
    findings.push({
      id: "heur-direct-ip-host",
      severity: "high",
      title: "URL basada en dirección IP directa",
      description: `El enlace utiliza la dirección IP '${hostname}' en lugar de un nombre de dominio. Patrón común en phishing para eludir análisis de reputación de dominio.`,
      evidence: `Host: ${hostname}`,
    });
    score += 30;
  }

  // 2. Detección de caracteres de autenticación @ en la URL (Camuflaje de destino)
  if (raw.includes("@")) {
    findings.push({
      id: "heur-at-symbol-trick",
      severity: "critical",
      title: "Uso malicioso del símbolo '@' en la URL",
      description: "La sintaxis incluye '@', lo que provoca que los navegadores ignoren todo el texto previo y conecten exclusivamente al host posterior.",
      evidence: raw,
    });
    score += 45;
  }

  // 3. Detección de Punycode / IDN Homoglyphs (Suplantación visual de caracteres)
  if (hostname.includes("xn--")) {
    findings.push({
      id: "heur-punycode-homoglyph",
      severity: "critical",
      title: "Ataque Homógrafo IDN detectado (Punycode xn--)",
      description: `El dominio utiliza codificación Punycode ('${hostname}') para simular caracteres latinos usando alfabetos cirílicos o griegos idénticos a la vista.`,
      evidence: hostname,
    });
    score += 50;
  }

  // 4. Detección de Acortadores de URL
  if (SHORTENERS.has(hostname)) {
    findings.push({
      id: "heur-url-shortener",
      severity: "medium",
      title: "Servicio de acortamiento de URLs",
      description: `El enlace emplea '${hostname}' para ocultar el destino final del usuario.`,
    });
    score += 15;
  }

  // 5. Análisis de TLD sospechoso
  const domainParts = hostname.split(".");
  const tld = "." + (domainParts[domainParts.length - 1] || "");
  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push({
      id: "heur-suspicious-tld",
      severity: "medium",
      title: `TLD de alto riesgo estadístico (${tld})`,
      description: `La extensión '${tld}' presenta tasas desproporcionadas de abuso y registro anónimo gratuito/descartable.`,
    });
    score += 20;
  }

  // 6. Subdominios Excesivos (Deep subdomain nesting)
  const subdomainCount = Math.max(0, domainParts.length - 2);
  if (subdomainCount >= 3) {
    findings.push({
      id: "heur-excessive-subdomains",
      severity: "medium",
      title: `Estructura de subdominios excesiva (${subdomainCount} niveles)`,
      description: `Jerarquía profunda ('${hostname}') utilizada comúnmente para simular dominios legítimos en dispositivos móviles donde la barra de direcciones se trunca.`,
    });
    score += 20;
  }

  // 7. Entropía de Shannon del Hostname (Detección de DGA / Dominios aleatorios)
  const baseName = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : hostname;
  const hostEntropy = entropy(baseName);
  if (hostEntropy > 3.75 && baseName.length > 8) {
    findings.push({
      id: "heur-high-domain-entropy",
      severity: "high",
      title: `Alta aleatoriedad en el dominio (Posible DGA / Entropía: ${hostEntropy.toFixed(2)})`,
      description: `El nombre '${baseName}' posee una combinación aleatoria atípica, compatible con algoritmos de generación de dominios (DGA) de botnets y malware.`,
      evidence: `Entropía: ${hostEntropy.toFixed(2)} bits (umbral DGA: > 3.75)`,
    });
    score += 25;
  }

  // 8. Typosquatting y Suplantación de Marcas (Levenshtein)
  const fullText = (hostname + " " + pathname).replace(/[-_.]/g, " ");
  for (const brand of TARGET_BRANDS) {
    // Si la marca está contenida exactamente pero NO es el dominio legítimo
    const isExactBrand = domainParts.length >= 2 && domainParts[domainParts.length - 2] === brand;
    if (fullText.includes(brand) && !isExactBrand) {
      findings.push({
        id: `heur-brand-impersonation-${brand}`,
        severity: "critical",
        title: `Suplantación de marca detectada: ${brand.toUpperCase()}`,
        description: `El recurso incluye el nombre comercial '${brand}' sin pertenecer a la entidad oficial. Vector inequívoco de phishing.`,
        evidence: `Marca: ${brand} en '${hostname}${pathname}'`,
      });
      score += 45;
      break;
    }

    // Comprobación de distancia Levenshtein (ej. "paypa1", "g00gle")
    if (baseName !== brand && baseName.length >= 4) {
      const dist = levenshtein(baseName, brand);
      if (dist === 1 || (dist === 2 && baseName.length >= 7)) {
        findings.push({
          id: `heur-typosquatting-${brand}`,
          severity: "critical",
          title: `Typosquatting detectado sobre ${brand.toUpperCase()}`,
          description: `El dominio '${baseName}' imita intencionalmente la grafía de '${brand}' con una alteración mínima (distancia Levenshtein: ${dist}).`,
          evidence: `'${baseName}' similar a '${brand}' (distancia: ${dist})`,
        });
        score += 50;
        break;
      }
    }
  }

  // 9. Detección de Palabras Clave Sensibles en Path o Query
  const matchedKeywords = SENSITIVE_KEYWORDS.filter(kw => (pathname + search).includes(kw));
  if (matchedKeywords.length >= 2) {
    findings.push({
      id: "heur-sensitive-keywords",
      severity: "medium",
      title: `Ruta de acceso con términos sensibles (${matchedKeywords.slice(0, 3).join(", ")})`,
      description: `La ruta simula paneles de autenticación o cobranza bancaria: ${matchedKeywords.join(", ")}.`,
    });
    score += 15;
  }

  // 10. Detección de Base64 / Credenciales codificadas en Query String
  const base64Matches = search.match(/[a-zA-Z0-9+/=]{20,}/g);
  if (base64Matches) {
    for (const b64 of base64Matches) {
      try {
        const decoded = Buffer.from(b64, "base64").toString("utf8");
        if (decoded.includes("@") || decoded.includes("http") || decoded.includes("{")) {
          findings.push({
            id: "heur-base64-payload",
            severity: "high",
            title: "Carga útil Base64 detectada en parámetros de la URL",
            description: "La URL transporta datos sensibles codificados en Base64 (posible correo víctima prellenado para phishing).",
            evidence: `Decodificado: ${decoded.slice(0, 50)}...`,
          });
          score += 25;
          break;
        }
      } catch {
        // Ignorar si no es base64 válido
      }
    }
  }

  return {
    score: Math.min(100, score),
    findings,
    iocs,
  };
}
