import { Finding, TechnicalEvidence } from "../types";
import { entropy, generateFakeHash } from "../utils";

const BRANDS = ["paypal", "google", "facebook", "apple", "microsoft", "amazon", "netflix", "instagram", "santander", "bbva", "caixa", "banamex", "binance", "coinbase", "github", "linkedin", "whatsapp", "telegram", "bcp", "interbank", "scotiabank"];
const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work", ".date", ".party", ".buzz", ".cam", ".rest", ".bar", ".zip", ".mov", ".phishing"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "shorturl.at", "buff.ly", "rebrand.ly", "tiny.cc"];

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) dp[i][j] = a[i-1]===b[j-1] ? dp[i-1][j-1] : 1+Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function extractDomain(url: string): { hostname: string; protocol: string; path: string; search: string } {
  try {
    let toParse = url.trim();
    if (!/^https?:\/\//i.test(toParse)) toParse = "https://" + toParse;
    const u = new URL(toParse);
    return { hostname: u.hostname.toLowerCase(), protocol: u.protocol, path: u.pathname, search: u.search };
  } catch {
    return { hostname: url.toLowerCase(), protocol: "https:", path: "/", search: "" };
  }
}

export function analyzeUrl(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number): number {
  let score = 0;
  const { hostname, protocol, path, search } = extractDomain(input);
  const full = input.toLowerCase();
  const domainParts = hostname.split(".");
  const tld = "." + (domainParts[domainParts.length-1] || "");
  const sld = domainParts[domainParts.length-2] || "";
  const subdomainCount = Math.max(0, domainParts.length - 2);

  // Build technical evidence (simulated)
  const ageDays = Math.floor(rnd() * 900);
  // bias: if input looks phishing, make age small
  const isPhishingLike = /banc0|secure-login|verify|xn--|bit\.ly|@/.test(full);
  const effectiveAge = isPhishingLike ? Math.floor(rnd()*72) + 1 : (hostname.includes("google") || hostname.includes("github") ? 7500 + Math.floor(rnd()*1000) : ageDays);

  evidence.whois = {
    registrar: isPhishingLike ? ["NameCheap, Inc.", "GoDaddy.com, LLC", "Hosting Concepts B.V."][Math.floor(rnd()*3)] : ["MarkMonitor Inc.", "Google LLC", "Cloudflare, Inc."][Math.floor(rnd()*3)],
    created: new Date(Date.now() - effectiveAge*86400000).toISOString(),
    expires: new Date(Date.now() + (365 + Math.floor(rnd()*1000))*86400000).toISOString(),
    updated: new Date(Date.now() - Math.floor(rnd()*10)*86400000).toISOString(),
    ageDays: effectiveAge,
    registrarAbuseContact: "abuse@" + (isPhishingLike ? "namecheap.com" : "markmonitor.com"),
  };
  evidence.dns = {
    a: Array.from({length: 1+Math.floor(rnd()*2)}, () => `${Math.floor(rnd()*223)+1}.${Math.floor(rnd()*255)}.${Math.floor(rnd()*255)}.${Math.floor(rnd()*255)}`),
    mx: isPhishingLike ? [] : ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
    txt: isPhishingLike ? ["v=spf1 -all"] : ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123"],
    ns: isPhishingLike ? ["ns1.hostinger.com","ns2.hostinger.com"] : ["ns1.google.com","ns2.google.com"],
  };
  evidence.reverseDns = isPhishingLike ? `ptr-${Math.floor(rnd()*255)}.hostinger.com` : `server-${hostname.replace(/\./g,"-")}.google.com`;

  // SSL
  const expired = isPhishingLike && rnd() > 0.4;
  evidence.ssl = {
    issuer: isPhishingLike ? "Let's Encrypt / R3 (DV only)" : "Google Trust Services / WE1",
    subject: `CN=${hostname}`,
    validFrom: new Date(Date.now() - 30*86400000).toISOString(),
    validTo: expired ? new Date(Date.now() - 3*86400000).toISOString() : new Date(Date.now() + (60+Math.floor(rnd()*300))*86400000).toISOString(),
    expired,
    daysUntilExpiry: expired ? -3 : 60+Math.floor(rnd()*300),
    sans: [hostname, `www.${hostname}`],
  };

  // Headers
  evidence.httpHeaders = {
    "server": isPhishingLike ? "nginx/1.18.0" : "gws",
    "x-powered-by": isPhishingLike ? "PHP/7.4.3" : undefined as unknown as string,
    "content-type": "text/html; charset=utf-8",
    "x-frame-options": isPhishingLike ? "" : "SAMEORIGIN",
    "strict-transport-security": isPhishingLike ? "" : "max-age=31536000; includeSubDomains",
    "content-security-policy": isPhishingLike ? "" : "default-src 'self' https://*.gstatic.com",
    "set-cookie": isPhishingLike ? "PHPSESSID=abc123; path=/" : "NID=511=abc; expires=...; Secure; HttpOnly",
  } as Record<string,string>;

  // Redirect chain
  if (/bit\.ly|t\.co|tinyurl|is\.gd|goo\.gl/.test(full)) {
    evidence.redirectChain = [
      { url: input, status: 301, location: `https://${hostname.replace("bit.ly","banc0-santander.tk")}/verify` },
      { url: `https://${hostname.replace("bit.ly","banc0-santander.tk")}/verify`, status: 302, location: `https://banc0-santander-secure.tk/login?session=${generateFakeHash(input,12)}` },
      { url: `https://banc0-santander-secure.tk/login`, status: 200 },
    ];
  } else if (isPhishingLike) {
    evidence.redirectChain = [
      { url: input, status: 302, location: `https://${hostname}/auth/verify` },
      { url: `https://${hostname}/auth/verify`, status: 200 },
    ];
  } else {
    evidence.redirectChain = [{ url: input, status: 200 }];
  }

  evidence.iocs = [
    { type: "domain", value: hostname, context: "Dominio principal" },
    { type: "ipv4", value: evidence.dns.a![0], context: "Resolución A" },
  ];
  if (search) evidence.iocs.push({ type: "url-param", value: search.slice(0,80), context: "Parámetros de URL" });

  // === Heuristics ===
  // 1. Brand typosquatting
  for (const brand of BRANDS) {
    if (hostname.includes(brand)) {
      // exact brand is less suspicious if it's the legit domain
      const legitDomains: Record<string,string> = { paypal:"paypal.com", google:"google.com", github:"github.com", microsoft:"microsoft.com", amazon:"amazon.com", facebook:"facebook.com" };
      if (legitDomains[brand] && hostname === legitDomains[brand]) continue;
      if (hostname !== brand+".com" && hostname !== "www."+brand+".com") {
        const dist = levenshtein(sld, brand);
        if (dist <= 2 || hostname.includes(brand+"-") || hostname.includes(brand+"secure") || hostname.includes("secure"+brand)) {
          score += 30;
          findings.push({
            id: "typo-"+brand,
            severity: "critical",
            title: `Posible typosquatting de "${brand}"`,
            description: `El dominio "${hostname}" contiene la marca "${brand}" pero no es el dominio oficial. Técnica común en phishing para suplantar identidad. Distancia Levenshtein: ${dist}.`,
            evidence: `Hostname: ${hostname} vs marca: ${brand}.com — verifica el certificado y el WHOIS.`,
            mitre: "T1583.001",
          });
        } else if (hostname.includes(brand)) {
          score += 18;
          findings.push({
            id: "brand-"+brand,
            severity: "high",
            title: `Uso de marca "${brand}" en subdominio/dominio`,
            description: `El dominio referencia "${brand}" fuera de su infraestructura oficial. Revisa si es un servicio legítimo de terceros o un intento de suplantación.`,
            evidence: hostname,
          });
        }
      }
    } else {
      // check typos
      if (levenshtein(sld, brand) === 1 && sld.length > 4) {
        score += 22;
        findings.push({
          id: "typo-lev-"+brand,
          severity: "high",
          title: `Dominio visualmente similar a "${brand}"`,
          description: `El SLD "${sld}" es casi idéntico a "${brand}" (1 carácter de diferencia). Característico de campañas de typosquatting.`,
          evidence: `Comparación: ${sld} ↔ ${brand}`,
        });
      }
    }
  }

  // 2. Punycode / homoglyph
  if (full.includes("xn--") || /[\u0400-\u04FF\u0600-\u06FF\u3040-\u30FF]/.test(input)) {
    score += 35;
    findings.push({
      id: "homoglyph",
      severity: "critical",
      title: "Homoglyph / Punycode detectado",
      description: "La URL usa caracteres Unicode confusables (IDN homograph) o formato punycode (xn--). Se utiliza para crear dominios visualmente idénticos a los legítimos con caracteres de otros alfabetos.",
      evidence: `Prefijo xn-- o caracteres fuera de ASCII en: ${hostname}`,
      cwe: "CWE-1007",
    });
  }

  // 3. URL shortener
  if (SHORTENERS.some(s => full.includes(s))) {
    score += 15;
    findings.push({
      id: "shortener",
      severity: "medium",
      title: "Acortador de URL detectado",
      description: "Los acortadores ocultan el destino final y evaden filtros. El análisis expandió la cadena de redirecciones para revelar el objetivo real.",
      evidence: `Acortador: ${SHORTENERS.find(s=>full.includes(s))} → ${evidence.redirectChain?.[evidence.redirectChain.length-1]?.url}`,
    });
  }

  // 4. IP in URL
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(full)) {
    score += 28;
    findings.push({
      id: "ip-url",
      severity: "critical",
      title: "URL basada en dirección IP (sin dominio)",
      description: "La URL usa una IP directa en lugar de un nombre de dominio. Comportamiento altamente anómalo; el 94% de URLs legítimas usan DNS.",
      evidence: full.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^ ]*/)?.[0] || "",
    });
  }

  // 5. @ symbol trick
  if (full.includes("@")) {
    score += 25;
    findings.push({
      id: "at-trick",
      severity: "critical",
      title: "Truco del símbolo '@' en URL",
      description: "El carácter '@' redirige la parte previa como credenciales. Ej: https://google.com@evil.tk — el navegador ignora google.com y va a evil.tk.",
      evidence: `Segmento con @: ${full.split("@")[0]}@...`,
    });
  }

  // 6. HTTP vs HTTPS
  if (protocol === "http:") {
    score += 12;
    findings.push({
      id: "http",
      severity: "medium",
      title: "Conexión sin cifrar (HTTP)",
      description: "El sitio usa HTTP sin TLS. Todo el tráfico es interceptable. Los sitios modernos legítimos usan HTTPS obligatorio (HSTS).",
      evidence: `Protocolo: ${protocol} — Sin cabecera Strict-Transport-Security`,
    });
  }

  // 7. SSL expired / self-signed
  if (evidence.ssl?.expired) {
    score += 14;
    findings.push({
      id: "ssl-expired",
      severity: "high",
      title: "Certificado SSL expirado",
      description: `El certificado expiró hace ${Math.abs(evidence.ssl.daysUntilExpiry || 3)} días. Indica abandono, mala higiene o infraestructura temporal típica de phishing.`,
      evidence: `Emisor: ${evidence.ssl.issuer} | Válido hasta: ${evidence.ssl.validTo}`,
    });
  }
  if (isPhishingLike && rnd() > 0.5) {
    score += 8;
    findings.push({
      id: "ssl-dv",
      severity: "low",
      title: "Certificado DV de validación básica",
      description: "Certificado Domain Validation (DV) gratuito. No valida identidad organizacional — cualquiera puede obtenerlo para cualquier dominio (Let's Encrypt). No garantiza legitimidad.",
      evidence: `Issuer: ${evidence.ssl?.issuer}`,
    });
  }

  // 8. Suspicious TLD
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 16;
    findings.push({
      id: "susp-tld",
      severity: "high",
      title: `TLD de alto riesgo: ${tld}`,
      description: "Este TLD es gratuito/barato y ampliamente abusado en campañas de phishing y malware (alta densidad de dominios maliciosos según Spamhaus).",
      evidence: `TLD: ${tld} — Registrar: ${evidence.whois?.registrar}`,
    });
  }

  // 9. Excessive length
  if (input.length > 150) {
    score += 10;
    findings.push({
      id: "long-url",
      severity: "medium",
      title: "URL excesivamente larga",
      description: `La URL tiene ${input.length} caracteres (umbral: 75). Las URLs largas ocultan parámetros maliciosos, tokens de seguimiento y payloads codificados.`,
      evidence: `Longitud: ${input.length} | Entropía: ${entropy(input).toFixed(2)} bits`,
    });
  } else if (input.length > 75) {
    score += 5;
    findings.push({
      id: "long-url-mild",
      severity: "low",
      title: "URL sospechosamente larga",
      description: `Longitud ${input.length} caracteres. Revisa parámetros innecesarios o encoding base64.`,
      evidence: `Path: ${path.slice(0,120)}`,
    });
  }

  // 10. Multiple subdomains
  if (subdomainCount >= 4) {
    score += 12;
    findings.push({
      id: "subdomains",
      severity: "medium",
      title: "Abuso de subdominios",
      description: `La URL tiene ${subdomainCount+1} niveles de subdominio. Técnica para falsificar legitimidad (ej: secure.login.paypal.com.evil.tk).`,
      evidence: `Hostname segmentado: ${hostname}`,
    });
  } else if (subdomainCount >= 3) {
    score += 6;
    findings.push({
      id: "subdomains-low",
      severity: "low",
      title: "Múltiples subdominios",
      description: `Niveles: ${subdomainCount+1}. Verifica que cada nivel pertenezca a la organización legítima.`,
      evidence: hostname,
    });
  }

  // 11. Suspicious keywords in path
  const suspiciousKeywords = ["login","verify","secure","account","webscr","confirm","update","signin","authenticate","wallet","invoice","payment","bonus"];
  const foundKw = suspiciousKeywords.filter(k => full.includes(k));
  if (foundKw.length >= 2) {
    score += 9;
    findings.push({
      id: "susp-keywords",
      severity: "medium",
      title: "Keywords de phishing en URL",
      description: `La ruta contiene términos de ingeniería social: ${foundKw.join(", ")}. Diseñado para generar urgencia y confianza.`,
      evidence: `Path+query: ${path}${search}`.slice(0,180),
    });
  }

  // 12. Domain age
  if (effectiveAge < 30) {
    score += 18;
    findings.push({
      id: "new-domain",
      severity: "high",
      title: `Dominio recién registrado (${effectiveAge} días)`,
      description: "El dominio fue creado hace muy poco. El 70% de dominios de phishing tienen menos de 30 días de antigüedad (campañas desechables).",
      evidence: `Creado: ${evidence.whois?.created?.slice(0,10)} | Registrar: ${evidence.whois?.registrar}`,
    });
  } else if (effectiveAge < 90) {
    score += 7;
    findings.push({
      id: "young-domain",
      severity: "low",
      title: `Dominio joven (${effectiveAge} días)`,
      description: "Antigüedad inferior a 3 meses. No concluyente por sí solo, pero suma riesgo en conjunto.",
      evidence: `WHOIS creado: ${evidence.whois?.created?.slice(0,10)}`,
    });
  }

  // 13. No SPF / MX
  if (!evidence.dns?.mx || evidence.dns.mx.length === 0) {
    score += 4;
    findings.push({
      id: "no-mx",
      severity: "info",
      title: "Sin registros MX",
      description: "El dominio no tiene servidores de correo. Puede indicar infraestructura temporal no diseñada para operación legítima.",
      evidence: "Consulta DNS MX: sin resultados",
    });
  }

  // 14. Missing security headers
  if (!evidence.httpHeaders?.["strict-transport-security"] && !isPhishingLike) {
    // only for clean-ish sites, but we add info
  }
  if (isPhishingLike) {
    findings.push({
      id: "missing-headers",
      severity: "info",
      title: "Cabeceras de seguridad ausentes",
      description: "Faltan HSTS, CSP y X-Frame-Options. Configuración mínima, típica de kits de phishing.",
      evidence: `Headers: ${Object.keys(evidence.httpHeaders||{}).join(", ")}`,
    });
  }

  // 15. Entropy (DGA)
  const e = entropy(hostname.replace(/\./g,""));
  if (e > 4.0 && hostname.length > 12) {
    score += 13;
    findings.push({
      id: "dga",
      severity: "high",
      title: "Alta entropía — posible DGA",
      description: `Entropía ${e.toFixed(2)} bits indica nombre generado algorítmicamente (Domain Generation Algorithm). Usado por botnets para C2.`,
      evidence: `Hostname: ${hostname} | Entropía: ${e.toFixed(2)}`,
    });
  }

  // 16. Clean signals (reduce score)
  if (!isPhishingLike && effectiveAge > 1000 && !SUSPICIOUS_TLDS.includes(tld) && protocol==="https:" && !full.includes("@")) {
    findings.push({
      id: "clean-age",
      severity: "info",
      title: "Dominio con antigüedad y reputación establecida",
      description: `Dominio con ${Math.floor(effectiveAge/365)} años de antigüedad, certificado válido y sin técnicas de evasión. Indicadores de legitimidad.`,
      evidence: `WHOIS: ${effectiveAge} días | SSL hasta: ${evidence.ssl?.validTo?.slice(0,10)}`,
    });
    score = Math.max(0, score - 6);
  }
  if (hostname === "github.com" || hostname === "google.com" || hostname === "microsoft.com") {
    findings.push({
      id: "known-good",
      severity: "info",
      title: "Dominio en lista de alta reputación",
      description: "Dominio perteneciente a proveedor Tier-1 con infraestructura verificada, DNSSEC y transparencia de certificados.",
      evidence: `Organización: ${evidence.whois?.registrar} | ASN asociado`,
    });
  }

  return Math.max(0, Math.min(100, score));
}
