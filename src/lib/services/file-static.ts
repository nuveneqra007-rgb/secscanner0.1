import crypto from "crypto";
import { Finding, Severity, TechnicalEvidence } from "../types";

const MAGIC_SIGNATURES: { magic: string; mime: string; desc: string; ext: string }[] = [
  { magic: "504b0304", mime: "application/zip", desc: "ZIP Archive / Android APK", ext: "apk" },
  { magic: "504b0506", mime: "application/zip", desc: "ZIP Archive (spanned/vacío)", ext: "zip" },
  { magic: "4d5a",     mime: "application/x-dosexec", desc: "Windows PE Executable / DLL", ext: "exe" },
  { magic: "7f454c46", mime: "application/x-elf", desc: "Linux ELF Binary", ext: "elf" },
  { magic: "cafebabe", mime: "application/java-vm", desc: "Java Class / Mach-O Fat", ext: "class" },
  { magic: "feedface", mime: "application/x-mach-binary", desc: "Mach-O Binary (32-bit)", ext: "macho" },
  { magic: "feedfacf", mime: "application/x-mach-binary", desc: "Mach-O Binary (64-bit)", ext: "macho" },
  { magic: "25504446", mime: "application/pdf", desc: "Documento PDF", ext: "pdf" },
  { magic: "d0cf11e0", mime: "application/x-ole-storage", desc: "Microsoft Compound Document", ext: "doc" },
  { magic: "52617221", mime: "application/x-rar-compressed", desc: "RAR Archive", ext: "rar" },
  { magic: "1f8b08",   mime: "application/gzip", desc: "GZIP Compressed Archive", ext: "gz" },
];

const DANGEROUS_PERMISSIONS: Record<string, { severity: Severity; desc: string }> = {
  "android.permission.SEND_SMS": {
    severity: "critical",
    desc: "Permite enviar SMS sin consentimiento — típico de troyanos bancarios para suscripciones premium y fraude.",
  },
  "android.permission.READ_SMS": {
    severity: "critical",
    desc: "Lee todos los SMS entrantes, incluyendo códigos de autenticación 2FA y mensajes bancarios OTP.",
  },
  "android.permission.RECEIVE_SMS": {
    severity: "critical",
    desc: "Intercepta mensajes SMS en tiempo real antes de que el usuario los note.",
  },
  "android.permission.READ_CONTACTS": {
    severity: "high",
    desc: "Exfiltración de agenda telefónica completa para campañas de propagación por spam.",
  },
  "android.permission.READ_CALL_LOG": {
    severity: "high",
    desc: "Historial completo de llamadas telefónicas — comportamiento habitual de spyware.",
  },
  "android.permission.CALL_PHONE": {
    severity: "high",
    desc: "Realiza llamadas telefónicas sin interacción del usuario.",
  },
  "android.permission.RECORD_AUDIO": {
    severity: "critical",
    desc: "Activación del micrófono en segundo plano — riesgo de espionaje ambiental.",
  },
  "android.permission.CAMERA": {
    severity: "high",
    desc: "Acceso encubierto a la cámara del dispositivo para captura de imágenes o video.",
  },
  "android.permission.ACCESS_FINE_LOCATION": {
    severity: "high",
    desc: "Geolocalización GPS exacta en tiempo real.",
  },
  "android.permission.REQUEST_INSTALL_PACKAGES": {
    severity: "critical",
    desc: "Permite instalar otros paquetes de aplicaciones (Dropper / Carga útil secundaria).",
  },
  "android.permission.SYSTEM_ALERT_WINDOW": {
    severity: "high",
    desc: "Superposición de ventanas (Overlay attack) utilizado para secuestrar pantallas de login bancario.",
  },
  "android.permission.BIND_DEVICE_ADMIN": {
    severity: "critical",
    desc: "Privilegios de Administrador de Dispositivo — impide la desinstalación manual de la app.",
  },
  "android.permission.RECEIVE_BOOT_COMPLETED": {
    severity: "medium",
    desc: "Persistencia tras el reinicio del sistema operativo.",
  },
  "android.permission.WRITE_EXTERNAL_STORAGE": {
    severity: "low",
    desc: "Escritura en almacenamiento compartido del dispositivo.",
  },
  "android.permission.READ_EXTERNAL_STORAGE": {
    severity: "low",
    desc: "Lectura de archivos personales almacenados en memoria externa.",
  },
};

export interface FileAnalysisResult {
  fileInfo: TechnicalEvidence["fileInfo"];
  permissions?: TechnicalEvidence["permissions"];
  findings: Finding[];
  riskContribution: number;
}

/**
 * Realiza un análisis estático 100% real sobre el buffer de un archivo binario o paquete APK.
 */
export function analyzeBuffer(buffer: Buffer, fileName: string): FileAnalysisResult {
  const findings: Finding[] = [];
  let riskScore = 0;

  // 1. Hashes criptográficos reales
  const md5 = crypto.createHash("md5").update(buffer).digest("hex");
  const sha1 = crypto.createHash("sha1").update(buffer).digest("hex");
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

  // 2. Entropía de Shannon real byte a byte
  const byteFreq = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i++) {
    byteFreq[buffer[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (byteFreq[i] > 0) {
      const p = byteFreq[i] / buffer.length;
      entropy -= p * Math.log2(p);
    }
  }

  // 3. Inspección de Magic Bytes
  const hexHeader = buffer.subarray(0, 8).toString("hex").toLowerCase();
  const matchedMagic = MAGIC_SIGNATURES.find(s => hexHeader.startsWith(s.magic));
  const detectedType = matchedMagic ? matchedMagic.desc : "Archivo Binario";

  // Alerta de camuflaje de ejecutable
  const isExe = hexHeader.startsWith("4d5a");
  const lowerName = fileName.toLowerCase();
  if (isExe && !lowerName.endsWith(".exe") && !lowerName.endsWith(".dll") && !lowerName.endsWith(".scr")) {
    findings.push({
      id: "spoofed-exe-extension",
      severity: "critical",
      title: "Extensión camuflada: Ejecutable Windows (MZ PE) disfrazado",
      description: `El archivo presenta firma binaria MZ (ejecutable de Windows) pero posee extensión '${fileName.split(".").pop()}'. Técnica frecuente en droppers para eludir filtros.`,
      evidence: `Magic Header: 0x4D5A (MZ) | Archivo: ${fileName}`,
    });
    riskScore += 50;
  }

  // Alerta de alta entropía (empaquetado o cifrado)
  if (entropy > 7.2) {
    findings.push({
      id: "high-entropy-packed",
      severity: "high",
      title: `Alta entropía detectada (${entropy.toFixed(2)} / 8.0)`,
      description: "Nivel de entropía elevado característico de ejecutables comprimidos con empaquetadores evasivos (UPX, Themida), código ofuscado o payloads cifrados de ransomware.",
      evidence: `Entropía Shannon: ${entropy.toFixed(3)} bits/byte (Umbral de empaquetado: > 7.2)`,
    });
    riskScore += 25;
  } else {
    findings.push({
      id: "entropy-normal",
      severity: "info",
      title: `Entropía estándar (${entropy.toFixed(2)} / 8.0)`,
      description: "Distribución uniforme de bytes dentro de los parámetros habituales de código no empaquetado.",
    });
  }

  // 4. Extracción real de permisos para APKs (contenedor ZIP)
  let permissions: TechnicalEvidence["permissions"] | undefined = undefined;
  if (lowerName.endsWith(".apk") || hexHeader.startsWith("504b0304")) {
    const extracted = extractAndroidPermissions(buffer, findings);
    permissions = extracted;
    const criticalPermCount = extracted.filter(p => p.severity === "critical").length;
    if (criticalPermCount > 0) {
      riskScore += Math.min(50, criticalPermCount * 20);
    }
  }

  const fileSizeMb = (buffer.length / (1024 * 1024)).toFixed(2);

  return {
    fileInfo: {
      name: fileName,
      size: `${fileSizeMb} MB (${buffer.length.toLocaleString()} bytes)`,
      type: detectedType,
      md5,
      sha1,
      sha256,
      entropy: Number(entropy.toFixed(2)),
      magic: matchedMagic ? `${matchedMagic.magic.toUpperCase()} (${matchedMagic.desc})` : hexHeader.slice(0, 8),
    },
    permissions,
    findings,
    riskContribution: riskScore,
  };
}

/**
 * Escanea el contenedor APK (formato ZIP) para extraer declaraciones de permisos Android.
 */
function extractAndroidPermissions(buffer: Buffer, findings: Finding[]): NonNullable<TechnicalEvidence["permissions"]> {
  const matchesSet = new Set<string>();
  const permissionRegex = /android\.permission\.[A-Z_0-9]+/g;

  // Procesar en chunks de 512 KB con solapamiento para no agotar el heap de V8 en Serverless
  const CHUNK_SIZE = 512 * 1024;
  const OVERLAP = 256;
  const maxScanBytes = Math.min(buffer.length, 4 * 1024 * 1024); // Estructura de manifest se ubica en los primeros 4 MB

  for (let offset = 0; offset < maxScanBytes; offset += (CHUNK_SIZE - OVERLAP)) {
    const end = Math.min(offset + CHUNK_SIZE, buffer.length);
    const chunkStr = buffer.subarray(offset, end).toString("latin1");
    const found = chunkStr.match(permissionRegex);
    if (found) {
      for (const p of found) matchesSet.add(p);
    }
    if (end >= buffer.length) break;
  }

  const matches = Array.from(matchesSet);
  const permissions: NonNullable<TechnicalEvidence["permissions"]> = [];

  for (const perm of matches) {
    const danger = DANGEROUS_PERMISSIONS[perm];
    const severity = danger ? danger.severity : "info";
    const description = danger ? danger.desc : "Permiso estándar de Android";

    permissions.push({
      name: perm,
      severity,
      description,
      requested: true,
    });

    if (danger && (danger.severity === "critical" || danger.severity === "high")) {
      findings.push({
        id: `perm-${perm.replace(/\./g, "-")}`,
        severity: danger.severity,
        title: `Permiso Android de alto riesgo: ${perm.split(".").pop()}`,
        description: danger.desc,
        evidence: `Declarado en APK: ${perm}`,
      });
    }
  }

  if (matches.length > 0) {
    findings.push({
      id: "apk-permissions-extracted",
      severity: "info",
      title: `Manifiesto de APK analizado (${matches.length} permisos declarados)`,
      description: "Extracción estática completada sobre el contenedor de la aplicación.",
    });
  }

  return permissions;
}
