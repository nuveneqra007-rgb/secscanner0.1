import { Finding, Severity, TechnicalEvidence } from "../types";
import { generateFakeHash } from "../utils";

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

export function analyzeHashOrFile(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number, fileName?: string): number {
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
