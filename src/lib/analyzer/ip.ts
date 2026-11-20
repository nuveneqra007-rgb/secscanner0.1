import { Finding, Severity, TechnicalEvidence } from "../types";
import { hashString } from "../utils";

export function analyzeIp(input: string, findings: Finding[], evidence: TechnicalEvidence, rnd: () => number): number {
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
  evidence.dns = { ptr: evidence.reverseDns };

  // Ports
  const commonPorts: { port: number; service: string; risk: Severity }[] = [
    { port:22, service:"SSH", risk:"medium" },
    { port:80, service:"HTTP", risk:"low" },
    { port:443, service:"HTTPS", risk:"low" },
    { port:21, service:"FTP", risk:"high" },
    { port:23, service:"Telnet", risk:"critical" },
    { port:3389, service:"RDP", risk:"critical" },
    { port:445, service:"SMB", risk:"critical" },
    { port:3306, service:"MySQL", risk:"high" },
    { port:6379, service:"Redis", risk:"high" },
    { port:27017, service:"MongoDB", risk:"high" },
  ];
  // choose open ports based on score
  let openPorts: typeof commonPorts = [];
  if (isTor || abuseScore>70) openPorts = commonPorts.filter(()=> rnd()>0.4).slice(0,5+Math.floor(rnd()*4));
  else if (abuseScore>40) openPorts = commonPorts.filter(()=> rnd()>0.7).slice(0,3);
  else openPorts = ([{port:443,service:"HTTPS",risk:"low" as Severity},{port:80,service:"HTTP",risk:"low" as Severity}]).slice(0, rnd()>0.5?2:1);
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
