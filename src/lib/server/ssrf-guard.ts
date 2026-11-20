import { isIP } from "net";

/**
 * Rangos de direcciones IP privadas, loopback, link-local y reservadas.
 */
const BLOCKED_IP_REGEXES = [
  /^127\./,                                    // Loopback IPv4 (127.0.0.0/8)
  /^10\./,                                     // Red privada Clase A (10.0.0.0/8)
  /^172\.(1[6-9]|2\d|3[01])\./,                // Red privada Clase B (172.16.0.0/12)
  /^192\.168\./,                               // Red privada Clase C (192.168.0.0/16)
  /^169\.254\./,                               // Link-local / APIPA (169.254.0.0/16)
  /^0\./,                                      // Red origen actual (0.0.0.0/8)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // Espacio compartido CGNAT (100.64.0.0/10)
  /^198\.(18|19)\./,                           // Red de benchmark (198.18.0.0/15)
  /^(::1|fc00:|fd00:|fe80:)/i,                 // IPv6 loopback, ULA, link-local
];

/**
 * Nombres de host bloqueados que corresponden a metadatos de nube o servicios internos.
 */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "169.254.169.254",            // AWS, Azure, GCP, DigitalOcean Instance Metadata
  "metadata.google.internal",    // GCP Metadata Service
  "metadata.google.com",
  "instance-data",              // EC2 Legacy Metadata
  "0.0.0.0",
  "::1",
  "::",
]);

/**
 * Dominios públicos de resolución comodín comúnmente abusados para DNS Rebinding o SSRF.
 */
const REBINDING_DOMAINS = [
  "nip.io",
  "sslip.io",
  "localtest.me",
  "vcap.me",
  "lvh.me",
  "burpcollaborator.net",
  "oastify.com",
];

/**
 * Normaliza representaciones alternativas de IP (IPv6-mapped IPv4, decimales, hexadecimales u octales)
 * a su formato canónico de dirección IPv4 o IPv6.
 */
export function canonicalizeIp(rawIp: string): string {
  let clean = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, "");

  // 1. Manejo de direcciones IPv6-Mapped IPv4 (ej. ::ffff:127.0.0.1 o ::ffff:7f00:1)
  if (clean.startsWith("::ffff:")) {
    const rest = clean.slice(7);
    if (rest.includes(":")) {
      const hexParts = rest.split(":");
      if (hexParts.length === 2) {
        const p1 = parseInt(hexParts[0], 16);
        const p2 = parseInt(hexParts[1], 16);
        if (!isNaN(p1) && !isNaN(p2)) {
          return `${(p1 >> 8) & 255}.${p1 & 255}.${(p2 >> 8) & 255}.${p2 & 255}`;
        }
      }
    } else {
      clean = rest;
    }
  }

  // 2. Manejo de representación IPv4 entera decimal (ej. 2130706433 -> 127.0.0.1)
  if (/^\d+$/.test(clean)) {
    const num = Number(clean);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  // 3. Manejo de representación hexadecimal completa (ej. 0x7f000001 -> 127.0.0.1)
  if (/^0x[0-9a-f]+$/i.test(clean)) {
    const num = parseInt(clean, 16);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      return `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  // 4. Manejo de octetos mixtos con base octal o hex (ej. 0177.0.0.1 o 0x7f.0.0.1)
  if (/^[0-9a-fx.]+/i.test(clean)) {
    const parts = clean.split(".");
    if (parts.length >= 2 && parts.length <= 4) {
      const normalizedParts: number[] = [];
      for (const p of parts) {
        let val = NaN;
        if (p.startsWith("0x") || p.startsWith("0X")) {
          val = parseInt(p, 16);
        } else if (p.startsWith("0") && p.length > 1) {
          val = parseInt(p, 8);
        } else {
          val = parseInt(p, 10);
        }
        if (isNaN(val) || val < 0 || val > 255) break;
        normalizedParts.push(val);
      }
      if (normalizedParts.length === 4) {
        return normalizedParts.join(".");
      }
    }
  }

  return clean;
}

/**
 * Verifica si una dirección IP pertenece a un rango privado, reservado o de loopback.
 */
export function isPrivateIp(ip: string): boolean {
  const canonical = canonicalizeIp(ip);
  return BLOCKED_IP_REGEXES.some(regex => regex.test(canonical));
}

/**
 * Validación previa (Pre-DNS): Determina si el indicador apunta directamente
 * a una dirección privada, localhost o un servicio de metadatos antes de resolver.
 */
export function isSsrfTarget(target: string): boolean {
  try {
    let hostname = target.trim();

    // Si tiene puerto o formato URL, extraer el hostname
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(hostname)) {
      const parsed = new URL(hostname);
      hostname = parsed.hostname;
    } else {
      // Eliminar paths o puertos residuales (ej. 127.0.0.1:8080 o dominio.com/ruta)
      hostname = hostname.split("/")[0].split(":")[0];
    }

    hostname = hostname.toLowerCase().replace(/^\[|\]$/g, "");

    if (!hostname) return true;

    // Normalizar si viene en formato canónico/IP
    const canonical = canonicalizeIp(hostname);

    // 1. Hostnames de infraestructura interna o metadatos
    if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_HOSTNAMES.has(canonical)) {
      return true;
    }

    // 2. Comprobar dominios especiales de pruebas o internos
    if (
      hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal") ||
      hostname.endsWith(".corp") ||
      hostname.endsWith(".home")
    ) {
      return true;
    }

    // 3. Bloquear dominios comodín comunes de DNS rebinding (ej. 127.0.0.1.nip.io)
    if (REBINDING_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d))) {
      return true;
    }

    // 4. Comprobar si es una dirección IP en un rango prohibido (canónica o directa)
    if (isIP(hostname) || isIP(canonical) || isPrivateIp(canonical)) {
      return isPrivateIp(canonical);
    }

    return false;
  } catch {
    // Si no se puede parsear limpiamente, bloquear por principio de mínimo privilegio
    return true;
  }
}
