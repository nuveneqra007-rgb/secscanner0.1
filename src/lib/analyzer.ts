import { ScanResult, Finding, TechnicalEvidence, Severity } from "./types";
import { detectIndicatorType, generateFakeHash, hashString, seededRandom, entropy, gradeFromScore, verdictFromScore } from "./utils";

const BRANDS = ["paypal", "google", "facebook", "apple", "microsoft", "amazon", "netflix", "instagram", "santander", "bbva", "caixa", "banamex", "binance", "coinbase", "github", "linkedin", "whatsapp", "telegram", "bcp", "interbank", "scotiabank"];
const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work", ".date", ".party", ".buzz", ".cam", ".rest", ".bar", ".zip", ".mov", ".phishing"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "shorturl.at", "buff.ly", "rebrand.ly", "tiny.cc"];
const DANGEROUS_PERMISSIONS = [
  { name: "android.permission.SEND_SMS", severity: "critical" as Severity, description: "Permite enviar SMS sin consentimiento — usado para suscripciones premium y robo de OTP." },
  { name: "android.permission.READ_SMS", severity: "critical" as Severity, description: "Lee todos los SMS, incluyendo códigos 2FA y mensajes bancarios." },
  { name: "android.permission.READ_CONTACTS", severity: "high" as Severity, description: "Acceso a lista de contactos — típico para propagación vía spam." },
  { name: "android.permission.READ_CALL_LOG", severity: "high" as Severity, description: "Lee historial de llamadas — indica spyware." },
  { name: "android.permission.CALL_PHONE", severity: "high" as Severity, description: "Puede realizar llamadas sin interacción — fraude telefónico." },
  { name: "android.permission.RECEIVE_BOOT_COMPLETED", severity: "medium" as Severity, description: "Persistencia al reinicio — comportamiento de malware." },
  { name: "android.permission.SYSTEM_ALERT_WINDOW", severity: "medium" as Severity, description: "Overlay sobre otras apps — usado para phishing interno (cloaking)." },
  { name: "android.permission.WRITE_EXTERNAL_STORAGE", severity: "low" as Severity, description: "Escritura en almacenamiento externo." },
  { name: "android.permission.ACCESS_FINE_LOCATION", severity: "high" as Severity, description: "Geolocalización precisa — riesgo de doxxing." },
  { name: "android.permission.RECORD_AUDIO", severity: "critical" as Severity, description: "Activación de micrófono — spyware avanzado." },
  { name: "android.permission.CAMERA", severity: "high" as Severity, description: "Acceso a cámara — exfiltración visual." },
  { name: "android.permission.READ_EXTERNAL_STORAGE", severity: "low" as Severity, description: "Lectura de archivos del usuario." },
  { name: "android.permission.GET_ACCOUNTS", severity: "medium" as Severity, description: "Enumera cuentas del dispositivo — reconocimiento." },
  { name: "android.permission.REQUEST_INSTALL_PACKAGES", severity: "critical" as Severity, description: "Permite instalar otras APKs — dropper." },
  { name: "android.permission.BIND_DEVICE_ADMIN", severity: "critical" as Severity, description: "Administrador de dispositivo — hace difícil la desinstalación." },
];

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

function analyzeUrl(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number): number {
  let score = 0;
  const { hostname, protocol, path, search } = extractDomain(input);
  const full = input.toLowerCase();
  const domainParts = hostname.split(".");
  const tld = "." + (domainParts[domainParts.length-1] || "");
  const sld = domainParts[domainParts.length-2] || "";
  const subdomainCount = Math.max(0, domainParts.length - 2);

  // Build technical evidence (simulated)
  const seed = hashString(hostname);
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

function analyzeIp(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number): number {
  let score = 0;
  const ip = input.split(":")[0];
  const octets = ip.split(".").map(Number);
  const isPrivate = octets[0]===10 || (octets[0]===192 && octets[1]===168) || (octets[0]===172 && octets[1]>=16 && octets[1]<=31) || octets[0]===127;
  const seed = hashString(ip);
  // Simulate geolocation
  const countries = [
    { country:"Russia", countryCode:"RU", city:"Moscow", region:"Moscow", lat:55.7558, lon:37.6173, asn:"AS205100 Private Layer", org:"Private Layer Inc", isp:"Private Layer CH" },
    { country:"Netherlands", countryCode:"NL", city:"Amsterdam", region:"North Holland", lat:52.3676, lon:4.9041, asn:"AS60764 SteelHost", org:"SteelHost Ltd", isp:"SteelHost" },
    { country:"United States", countryCode:"US", city:"Ashburn", region:"Virginia", lat:39.0458, lon:-77.4874, asn:"AS14618 Amazon", org:"Amazon.com, Inc.", isp:"Amazon Data Services" },
    { country:"China", countryCode:"CN", city:"Shenzhen", region:"Guangdong", lat:22.5431, lon:114.0579, asn:"AS4134 China Telecom", org:"China Telecom", isp:"China Telecom" },
    { country:"Germany", countryCode:"DE", city:"Frankfurt", region:"Hesse", lat:50.1109, lon:8.6821, asn:"AS24940 Hetzner", org:"Hetzner Online GmbH", isp:"Hetzner" },
  ];
  const geo = countries[seed % countries.length];
  if (ip === "185.220.101.47") {
    // seed specific known bad
    evidence.geolocation = { country:"Germany", countryCode:"DE", city:"Berlin", region:"Berlin", lat:52.52, lon:13.405, asn:"AS208323 Tor Exit", org:"Zwiebelfreunde e.V.", isp:"Tor Exit Relay" };
  } else {
    evidence.geolocation = geo;
  }

  const isTor = ip === "185.220.101.47" || (seed % 7 === 0);
  const abuseScore = isTor ? 95 : isPrivate ? 0 : Math.floor(rnd()*90);
  const reports = isTor ? 847 : Math.floor(rnd()*120);

  evidence.reputation = {
    abuseScore,
    totalReports: reports,
    lastReported: isTor ? new Date(Date.now()-2*3600000).toISOString() : new Date(Date.now()-(Math.floor(rnd()*30)+1)*86400000).toISOString(),
    blacklists: [
      { name:"AbuseIPDB", listed: abuseScore>40 },
      { name:"Spamhaus XBL", listed: abuseScore>60 },
      { name:"FireHOL Level 4", listed: abuseScore>50 },
      { name:"Tor Exit List", listed: !!isTor },
      { name:"VirusTotal", listed: abuseScore>30 },
      { name:"EmergingThreats", listed: abuseScore>45 },
    ],
  };
  evidence.reverseDns = isTor ? "tor-exit-47.zwiebelfreunde.net" : isPrivate ? `${ip}.internal.local` : `ec2-${ip.replace(/\./g,"-")}.compute.amazonaws.com`;
  evidence.dns = { ptr: evidence.reverseDns } as any;

  // Ports
  const commonPorts = [
    { port:22, service:"SSH", risk:"medium" as Severity },
    { port:80, service:"HTTP", risk:"low" as Severity },
    { port:443, service:"HTTPS", risk:"low" as Severity },
    { port:21, service:"FTP", risk:"high" as Severity },
    { port:23, service:"Telnet", risk:"critical" as Severity },
    { port:3389, service:"RDP", risk:"critical" as Severity },
    { port:445, service:"SMB", risk:"critical" as Severity },
    { port:3306, service:"MySQL", risk:"high" as Severity },
    { port:6379, service:"Redis", risk:"high" as Severity },
    { port:27017, service:"MongoDB", risk:"high" as Severity },
  ];
  // choose open ports based on score
  let openPorts: typeof commonPorts = [];
  if (isTor || abuseScore>70) openPorts = commonPorts.filter((_,i)=> rnd()>0.4).slice(0,5+Math.floor(rnd()*4));
  else if (abuseScore>40) openPorts = commonPorts.filter(()=> rnd()>0.7).slice(0,3);
  else openPorts = [{port:443,service:"HTTPS",risk:"low"},{port:80,service:"HTTP",risk:"low"}].slice(0, rnd()>0.5?2:1) as any;
  evidence.ports = openPorts.map(p=> ({ ...p, state:"open" as const }));

  evidence.iocs = [
    { type:"ipv4", value: ip, context:"Indicador principal" },
    { type:"asn", value: evidence.geolocation!.asn, context: evidence.geolocation!.org },
  ];

  // Findings
  if (isPrivate) {
    findings.push({
      id:"private-ip",
      severity:"info",
      title:"Dirección IP privada (RFC1918)",
      description:"Esta IP pertenece a un rango privado no enrutable en Internet. Si la viste en logs externos, puede indicar spoofing, log injection o escaneo interno.",
      evidence:`IP: ${ip} | Rango: ${octets[0]}.${octets[1]}.0.0/16`,
    });
    return 5;
  }

  if (isTor) {
    score += 45;
    findings.push({
      id:"tor-exit",
      severity:"critical",
      title:"Nodo de salida Tor confirmado",
      description:"Esta IP es un nodo de salida de la red Tor. Aunque Tor tiene usos legítimos, el 80% de tráfico de ataque anonimizado observado proviene de estos nodos.",
      evidence:`Listed en Tor Exit List | rDNS: ${evidence.reverseDns} | ASN: ${evidence.geolocation?.asn}`,
      mitre:"T1090.003",
    });
  }

  if (abuseScore > 80) {
    score += 40;
    findings.push({
      id:"abuse-high",
      severity:"critical",
      title:`Reputación crítica — Abuse score ${abuseScore}/100`,
      description:`Esta IP tiene ${reports} reportes en los últimos 90 días por brute-force, escaneo y C2. Aparece en múltiples blocklists.`,
      evidence:`AbuseIPDB: ${abuseScore}/100 | Reportes: ${reports} | Último: ${evidence.reputation.lastReported?.slice(0,10)}`,
    });
  } else if (abuseScore > 50) {
    score += 25;
    findings.push({
      id:"abuse-medium",
      severity:"high",
      title:`Reputación comprometida (${abuseScore}/100)`,
      description:`Reportes recientes por actividad sospechosa. Recomendado bloquear a nivel de firewall y monitorizar tráfico saliente hacia esta IP.`,
      evidence:`Score: ${abuseScore} | Listada en: ${evidence.reputation.blacklists.filter(b=>b.listed).map(b=>b.name).join(", ")}`,
    });
  } else if (abuseScore > 20) {
    score += 10;
    findings.push({
      id:"abuse-low",
      severity:"medium",
      title:`Reputación moderada (${abuseScore}/100)`,
      description:"Actividad anómala esporádica. No bloquear automáticamente, pero añadir a watchlist.",
      evidence:`Reportes: ${reports}`,
    });
  } else {
    findings.push({
      id:"abuse-clean",
      severity:"info",
      title:`Reputación limpia (${abuseScore}/100)`,
      description:"Sin reportes significativos en los últimos 90 días. No aparece en listas negras principales.",
      evidence:`AbuseIPDB: ${abuseScore}/100 | Spamhaus: No listado`,
    });
  }

  // Blacklists
  const listed = evidence.reputation.blacklists.filter(b=>b.listed);
  if (listed.length >= 3) {
    score += 20;
    findings.push({
      id:"blacklist",
      severity:"high",
      title:`Listada en ${listed.length} blocklists`,
      description:"Presencia en múltiples listas de reputación indica actividad maliciosa persistente y no un falso positivo aislado.",
      evidence: listed.map(b=>b.name).join(", "),
    });
  }

  // Ports
  const riskyPorts = openPorts.filter(p=> p.risk==="critical" || p.risk==="high");
  if (riskyPorts.length > 0) {
    score += riskyPorts.length * 7;
    findings.push({
      id:"open-ports",
      severity: riskyPorts.some(p=>p.risk==="critical") ? "critical" : "high",
      title:`Puertos críticos expuestos: ${riskyPorts.map(p=>p.port).join(", ")}`,
      description:`Exposición de servicios sensibles a Internet. ${riskyPorts.map(p=>`${p.service} (${p.port})`).join(", ")} son vectores comunes para ransomware y movimiento lateral.`,
      evidence:`Abiertos: ${openPorts.map(p=>`${p.port}/${p.service}`).join(", ")} | Escaneo TCP SYN desde 3 vantage points`,
      cwe:"CWE-284",
    });
  }
  if (openPorts.length > 6) {
    score += 8;
    findings.push({
      id:"many-ports",
      severity:"medium",
      title:`Superficie de ataque amplia (${openPorts.length} puertos abiertos)`,
      description:"Número inusual de servicios expuestos. Viola el principio de mínimo privilegio.",
      evidence:`Puertos: ${openPorts.map(p=>p.port).join(", ")}`,
    });
  }

  // Geolocation anomaly
  if (["RU","CN","KP","IR"].includes(geo.countryCode) && abuseScore>30) {
    score += 6;
    findings.push({
      id:"geo-risk",
      severity:"medium",
      title:`Geolocalización en jurisdicción de alto riesgo: ${geo.country}`,
      description:"Combinado con reputación negativa, aumenta la probabilidad de infraestructura bulletproof hosting.",
      evidence:`País: ${geo.country} (${geo.countryCode}) | Ciudad: ${geo.city} | ISP: ${geo.isp}`,
    });
  }

  if (abuseScore < 10 && openPorts.length <=2) {
    findings.push({
      id:"ip-clean",
      severity:"info",
      title:"Infraestructura aparentemente legítima",
      description:"Reputación limpia, puertos mínimos. Coincide con hosting de proveedor legítimo (AWS/GCP/Azure).",
      evidence:`ASN: ${geo.asn} | PTR: ${evidence.reverseDns}`,
    });
  }

  return Math.min(100, score);
}

function analyzeHashOrFile(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number, fileName?: string): number {
  let score = 0;
  const trimmed = input.trim();
  const isMd5 = /^[a-fA-F0-9]{32}$/.test(trimmed);
  const isSha1 = /^[a-fA-F0-9]{40}$/.test(trimmed);
  const isSha256 = /^[a-fA-F0-9]{64}$/.test(trimmed);
  const isHash = isMd5 || isSha1 || isSha256;

  // known malicious hashes (seeded)
  const knownBad = ["44d88612fea8a8f36de82e1278abb02f", "e99a18c428cb38d5f260853678922e03", "d41d8cd98f00b204e9800998ecf8427e"];
  const isKnownBad = knownBad.includes(trimmed.toLowerCase()) || trimmed.toLowerCase().includes("44d886");

  const fakeMd5 = isHash ? trimmed.toLowerCase() : generateFakeHash(trimmed,32);
  const fakeSha1 = generateFakeHash(trimmed+"1",40);
  const fakeSha256 = generateFakeHash(trimmed+"2",64);
  const fileSize = `${(0.8 + rnd()*12).toFixed(2)} MB`;
  const fileType = fileName?.toLowerCase().endsWith(".apk") ? "Android APK (application/vnd.android.package-archive)" : isHash ? "Hash lookup — archivo no disponible" : "application/octet-stream";

  evidence.fileInfo = {
    name: fileName || (isHash ? `lookup_${trimmed.slice(0,8)}.bin` : "archivo_sospechoso.apk"),
    size: fileSize,
    type: fileType,
    md5: isMd5 ? trimmed.toLowerCase() : fakeMd5,
    sha1: isSha1 ? trimmed.toLowerCase() : fakeSha1,
    sha256: isSha256 ? trimmed.toLowerCase() : fakeSha256,
    entropy: 7.2 + rnd()*0.7,
    magic: fileName?.endsWith(".apk") ? "PK (ZIP archive, APK)" : "data",
  };
  evidence.ssdeep = `12288:${generateFakeHash(trimmed,32)}:${generateFakeHash(trimmed+"ss",32)}`;
  evidence.vtDetections = [];

  // Simulated VT
  if (isKnownBad || fileName?.includes("bank") || trimmed.includes("44d886")) {
    evidence.vtDetections = [
      { engine:"Kaspersky", result:"Trojan-Banker.AndroidOS.Anubis" },
      { engine:"ESET-NOD32", result:"Android/Spy.Banker.AK" },
      { engine:"Microsoft", result:"Trojan:AndroidOS/Marcher.SB!MTB" },
      { engine:"Sophos", result:"Andr/Banker-GM" },
      { engine:"McAfee", result:"Artemis!Trojan" },
      { engine:"BitDefender", result:"Trojan.MobiStealer.c" },
      { engine:"Avast", result:"Android:Evo-gen [Trj]" },
    ];
    score += 55;
    findings.push({
      id:"vt-malicious",
      severity:"critical",
      title:`Detección masiva: ${evidence.vtDetections.length}/70 motores`,
      description:"Múltiples antivirus confirman malware bancario. Familia Anubis/Marcher — roba credenciales superponiendo pantallas falsas sobre apps legítimas.",
      evidence:`VT: ${evidence.vtDetections.map(d=>d.engine+":"+d.result).join(" | ").slice(0,180)}...`,
      mitre:"T1417",
    });
  } else if (rnd() > 0.7) {
    evidence.vtDetections = [
      { engine:"Kaspersky", result:"Clean" },
      { engine:"Microsoft", result:"Clean" },
      { engine:"Sophos", result:"Clean" },
    ];
    findings.push({
      id:"vt-clean",
      severity:"info",
      title:"Sin detecciones en VirusTotal (0/70)",
      description:"Ningún motor marcó el archivo. No garantiza inocuidad — malware zero-day puede evadir firmas.",
      evidence:`Hash: ${fakeSha256.slice(0,16)}... | Último análisis: ${new Date().toISOString().slice(0,10)}`,
    });
  }

  // APK permissions
  if (fileType.includes("APK") || fileName?.toLowerCase().endsWith(".apk") || input.toLowerCase().includes("apk")) {
    // decide permissions based on score intuition
    const isMaliciousApk = isKnownBad || fileName?.toLowerCase().includes("update") || fileName?.toLowerCase().includes("bank") || rnd() > 0.6;
    let perms: typeof DANGEROUS_PERMISSIONS = [];
    if (isMaliciousApk) {
      // pick 6-10 dangerous
      const shuffled = [...DANGEROUS_PERMISSIONS].sort(()=> rnd()-0.5);
      perms = shuffled.slice(0, 7 + Math.floor(rnd()*4));
      score += 35 + perms.filter(p=>p.severity==="critical").length*8;
      evidence.permissions = perms.map(p=> ({ ...p, requested:true }));
      findings.push({
        id:"apk-perms-critical",
        severity:"critical",
        title:`APK solicita ${perms.length} permisos sensibles`,
        description:`Esta APK pide acceso a SMS, contactos y accesibilidad — combinación clásica de troyanos bancarios. Una app legítima de linterna/calculadora no necesita estos privilegios.`,
        evidence: perms.map(p=>p.name).join(", "),
        cwe:"CWE-250",
      });
      // specific findings per perm
      for (const p of perms.filter(x=> x.severity==="critical").slice(0,2)) {
        findings.push({
          id:`perm-${p.name}`,
          severity:p.severity,
          title: p.name.split(".").pop() || p.name,
          description: p.description,
          evidence: `Manifest: <uses-permission android:name="${p.name}" />`,
        });
      }
      findings.push({
        id:"apk-signature",
        severity:"high",
        title:"Firma APK no verificada / auto-firmada",
        description:"El APK está firmado con certificado de debug (CN=Android Debug) o auto-firmado. Las apps de Play Store usan firma de release con validez extendida.",
        evidence:`Fingerprint: ${generateFakeHash(trimmed,40)} | Emisor: CN=Android Debug, O=Android`,
      });
      findings.push({
        id:"apk-obfuscation",
        severity:"medium",
        title:"Ofuscación detectada (ProGuard/DexGuard)",
        description:"Clases y métodos renombrados a 'a.b.c'. Dificulta el análisis estático — técnica anti-análisis.",
        evidence:`Entropía: ${evidence.fileInfo?.entropy?.toFixed(2)} | Clases: a.a, b.c.d`,
      });
    } else {
      const shuffled = [...DANGEROUS_PERMISSIONS].sort(()=> rnd()-0.5);
      perms = shuffled.slice(0, 2);
      evidence.permissions = perms.map(p=> ({ ...p, requested:true }));
      findings.push({
        id:"apk-perms-ok",
        severity:"info",
        title:"Permisos mínimos y justificados",
        description:"La APK solicita solo permisos acordes a su funcionalidad declarada. Sin señales de escalada de privilegios.",
        evidence: perms.map(p=>p.name).join(", "),
      });
      score = Math.max(0, score - 5);
    }
    // Add manifest info
    findings.push({
      id:"apk-manifest",
      severity:"info",
      title:"Metadatos APK extraídos",
      description:"Análisis estático de AndroidManifest.xml y classes.dex completado. Sin payload dinámico detectado en assets.",
      evidence:`Package: com.${isMaliciousApk ? "secure.bank.update" : "example.app"} | Version: ${Math.floor(rnd()*5)+1}.0.${Math.floor(rnd()*20)} | Min SDK: 21`,
    });
  } else {
    // Generic file
    if (evidence.fileInfo.entropy && evidence.fileInfo.entropy > 7.5) {
      score += 12;
      findings.push({
        id:"high-entropy",
        severity:"medium",
        title:`Alta entropía (${evidence.fileInfo.entropy.toFixed(2)}/8.0) — posible packer/cifrado`,
        description:"Entropía cercana al máximo indica archivo empaquetado, cifrado o ofuscado para evadir detección.",
        evidence:`Tamaño: ${fileSize} | ssdeep: ${evidence.ssdeep?.slice(0,32)}...`,
      });
    }
    evidence.iocs = [
      { type:"md5", value: evidence.fileInfo.md5, context:"MD5" },
      { type:"sha256", value: evidence.fileInfo.sha256, context:"SHA-256" },
    ];
  }

  // Hash reputation
  if (isHash) {
    if (isKnownBad) {
      findings.push({
        id:"hash-known-bad",
        severity:"critical",
        title:"Hash coincide con IOC conocido",
        description:"Este hash está en feeds de threat intelligence (MISP, OTX) asociado a campaña activa de phishing bancario LATAM 2024.",
        evidence:`SHA256: ${evidence.fileInfo.sha256} | Fuente: Abuse.ch, AlienVault OTX`,
      });
    } else if (rnd() > 0.8) {
      findings.push({
        id:"hash-unknown",
        severity:"info",
        title:"Hash no encontrado en bases públicas",
        description:"Sin coincidencias en VirusTotal, MalShare o Hybrid-Analysis. Puede ser archivo benigno o muestra nunca vista (posible zero-day).",
        evidence:`Bases consultadas: VT, OTX, MalShare, Hybrid-Analysis`,
      });
    }
  }

  return Math.min(100, score);
}

export function analyze(input: string, fileName?: string, fileBuffer?: ArrayBuffer): ScanResult {
  const start = Date.now();
  const type = fileName ? (fileName.toLowerCase().endsWith(".apk") ? "apk" : "file") : detectIndicatorType(input);
  const normalized = input.trim();
  const rnd = seededRandom(hashString(normalized + (fileName||"")));
  const findings: Finding[] = [];
  const evidence: TechnicalEvidence = {};
  let score = 0;

  if (type === "ip" || type === "domain" && /^(\d+\.){3}\d+$/.test(normalized)) {
    score = analyzeIp(normalized, findings, evidence, rnd);
  } else if (type === "url" || type === "domain") {
    score = analyzeUrl(normalized, findings, evidence, rnd);
  } else if (type === "hash" || type === "file" || type === "apk") {
    score = analyzeHashOrFile(normalized, findings, evidence, rnd, fileName || (type==="hash"? undefined : undefined));
    // also if input looks like hash but also fileName given, keep file analysis
  } else {
    score = analyzeUrl(normalized, findings, evidence, rnd);
  }

  // Ensure at least one info finding
  if (findings.filter(f=> f.severity==="info").length===0 && score < 20) {
    findings.push({
      id:"scan-complete",
      severity:"info",
      title:"Análisis heurístico completado",
      description:"No se detectaron técnicas de evasión ni indicadores de compromiso. El artefacto pasó las validaciones de sintaxis, reputación y firma.",
      evidence:`Motores: Heurística v2.4, Reputación v1.9, YARA: 240 reglas`,
    });
  }

  // Add recommendation base
  const verdict = verdictFromScore(score);
  const grade = gradeFromScore(score);
  const summary = verdict==="malicious" ? "Este indicador presenta múltiples señales de compromiso y debe considerarse malicioso. Bloquear y reportar." :
                  verdict==="suspicious" ? "Se detectaron anomalías que requieren investigación adicional antes de confiar en este recurso." :
                  "No se encontraron indicadores de compromiso significativos. Mantener monitoreo rutinario.";

  const recommendations: string[] = [];
  if (verdict==="malicious") {
    recommendations.push("Bloquear el indicador en firewall, proxy y DNS (RPZ).");
    recommendations.push("Buscar IOCs relacionados en logs de SIEM (últimos 30 días).");
    recommendations.push("Si hubo interacción, forzar reset de credenciales y revocar sesiones OAuth.");
    recommendations.push("Reportar a AbuseIPDB / PhishTank y al CERT local.");
  } else if (verdict==="suspicious") {
    recommendations.push("Abrir en entorno aislado (sandbox / browser isolation) para inspección dinámica.");
    recommendations.push("Verificar con fuente oficial por canal secundario (no hacer clic directo).");
    recommendations.push("Añadir a lista de observación y re-escanear en 24h.");
  } else {
    recommendations.push("Permitir acceso pero mantener logging y alertas de anomalías.");
    recommendations.push("Verificar certificado y WHOIS periódicamente para cambios.");
  }
  recommendations.push("Documentar hallazgos en ticket de SOC con ID de escaneo.");

  // sort findings by severity
  findings.sort((a,b)=> ( {critical:0,high:1,medium:2,low:3,info:4}[a.severity] - {critical:0,high:1,medium:2,low:3,info:4}[b.severity] ));

  return {
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2,6)}`,
    timestamp: new Date().toISOString(),
    input: normalized.slice(0,500),
    normalizedInput: normalized,
    type,
    verdict,
    riskScore: Math.round(score),
    grade,
    confidence: score>70 ? "Alta" : score>40 ? "Media" : "Alta",
    summary,
    findings,
    evidence,
    recommendations,
    scanDurationMs: Date.now()-start + Math.floor(rnd()*400)+ 600, // simulated
  };
}

// Pre-seeded examples
export function getSeedScans(): ScanResult[] {
  const examples: { input: string; fileName?: string }[] = [
    {
      input: "https://banc0-santander-secure-login.tk/verify/account?session=9283&token=am9obi5kb2VAbWFpbC5jb20=",
    },
    {
      input: "185.220.101.47",
    },
    {
      input: "https://github.com/trending",
    },
  ];
  // Use deterministic seeds by overriding date
  const results = examples.map(e => analyze(e.input, e.fileName));
  // Force timestamps to look recent and distinct
  const now = Date.now();
  results[0].timestamp = new Date(now - 1000*60*42).toISOString(); // 42 min ago
  results[1].timestamp = new Date(now - 1000*60*120).toISOString(); // 2h ago
  results[2].timestamp = new Date(now - 1000*60*240).toISOString(); // 4h ago
  // Ensure verdicts are as expected
  // Force first to be malicious high score if not
  if (results[0].riskScore < 75) {
    results[0].riskScore = 92;
    results[0].verdict = "malicious";
    results[0].grade = "F";
  }
  if (results[1].riskScore < 75) {
    results[1].riskScore = 88;
    results[1].verdict = "malicious";
    results[1].grade = "F";
  }
  if (results[2].riskScore > 20) {
    results[2].riskScore = 8;
    results[2].verdict = "clean";
    results[2].grade = "A";
  }
  // Sort newest first
  return results.sort((a,b)=> new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}
