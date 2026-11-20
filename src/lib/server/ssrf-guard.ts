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
  "[::1]",
]);

/**
 * Verifica si una dirección IP pertenece a un rango privado o reservado.
 */
export function isPrivateIp(ip: string): boolean {
  const cleanIp = ip.trim().replace(/^\[|\]$/g, "");
  return BLOCKED_IP_REGEXES.some(regex => regex.test(cleanIp));
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

    // 1. Hostnames de infraestructura interna o metadatos
    if (BLOCKED_HOSTNAMES.has(hostname)) {
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

    // 3. Comprobar si es una dirección IP en un rango prohibido
    if (isIP(hostname)) {
      return isPrivateIp(hostname);
    }

    return false;
  } catch {
    // Si no se puede parsear limpiamente, bloquear por principio de mínimo privilegio
    return true;
  }
}
