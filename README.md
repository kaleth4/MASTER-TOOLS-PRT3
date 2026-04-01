<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
╚██████╗   ██║   ██████╔╝███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
             V O L U M E   3  —  A D V A N C E D  &  S P E C I A L I Z E D
```

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![Tools](https://img.shields.io/badge/Tools-20-red?style=for-the-badge)
![ICS](https://img.shields.io/badge/ICS%20%7C%20IoT%20%7C%20Blockchain-orange?style=for-the-badge)
![AI](https://img.shields.io/badge/AI%20%7C%20Quantum%20%7C%20Forensics-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge&logo=linux)

> **20 herramientas avanzadas y especializadas — Volumen 3.**  
> Zero Trust · Ransomware · PKI · ICS/SCADA · IoT · Blockchain · Quantum · AI · Forensics

</div>

---

## 🗺️ Mapa del Toolkit

```
CYBER TOOLKIT — VOLUME 3
│
├── 🛡️  DEFENSA AVANZADA
│   ├── 01 · Zero Trust Model          → Simulate & assess Zero Trust policies
│   ├── 02 · Ransomware Detector       → Real-time filesystem + extension monitoring
│   ├── 03 · PKI Certificate Manager   → CA · certs · key generation (X.509)
│   └── 09 · Rootkit Detector          → Hidden procs · LKM · LD_PRELOAD · SUID
│
├── 🔴 AMENAZAS ESPECIALIZADAS
│   ├── 04 · Threat Intel Aggregator   → IOC lookup: AbuseIPDB · VirusTotal · Shodan
│   ├── 08 · DDoS Simulator            → Rate-based detection + attack type explainer
│   ├── 10 · AI Threat Predictor       → Naive Bayes + Z-score anomaly scoring
│   └── 20 · Malware Obfuscation       → Base64/Hex/PS decode + entropy analysis
│
├── 🌐 DOMINIOS EMERGENTES
│   ├── 13 · Smart Home / IoT          → Modbus/MQTT/Telnet/UPnP + default creds
│   ├── 14 · Container Security        → Docker inspect + Kubernetes pod audit
│   ├── 15 · Blockchain Security       → Solidity vulnerabilities + wallet validation
│   ├── 16 · SCADA / ICS               → Modbus · DNP3 · S7 · BACnet scanners
│   └── 18 · Quantum Cryptography      → BB84 simulation + post-quantum comparison
│
├── 🔬 ANÁLISIS & FORENSE
│   ├── 06 · Digital Forensics         → Timeline · hidden files · SUID · artifacts
│   ├── 11 · API Security Tester       → Auth bypass · IDOR · rate limit · injection
│   ├── 12 · Vuln Scanner Pro          → Service fingerprint + CVE database mapping
│   └── 19 · Side Channel Attack       → Timing attack demo + constant-time fix
│
└── 🧪 EDUCACIÓN & INVESTIGACIÓN
    ├── 05 · Secure Messaging          → E2E encryption sim (X25519 + AES-256-GCM)
    ├── 07 · Dark Web OSINT            → Tor check · methodology · .onion extraction
    ├── 17 · Cyber Range Generator     → CTF scenarios · lab network generator
    └── 03 · PKI Manager               → Full PKI stack: CA + server certs + inspect
```

---

## 🚀 Instalación rápida

```bash
git clone https://github.com/kaleth4/cyber-toolkit-v3.git
cd cyber-toolkit-v3
pip install -r requirements.txt
```

---

## 🛠️ Herramientas en detalle

### 🛡️ 01 · Zero Trust Security Model
Simula políticas **Never Trust, Always Verify** con 5 pilares (Identity, Devices, Network, Apps, Data).

```bash
# Simular solicitudes de acceso
python3 01_zero_trust_model.py --simulate

# Evaluar madurez Zero Trust de una organización
python3 01_zero_trust_model.py --assess

# Evaluar request específico
python3 01_zero_trust_model.py --request charlie finance_db
```
```
[19:43:01] charlie → finance_db  DENEGADO  Risk: 30
    ✗ MFA not enabled — access denied

[✓] Zero Trust Madurez: 60%
    Nivel 3 — Avanzado
    Identity      [██░] 2/3
    Network       [█░░] 1/3
```

---

### 🔐 02 · Ransomware Detector
Monitoreo en tiempo real de filesystem. Detecta extensiones, notas de rescate y alta entropía.

```bash
# Escaneo estático
python3 02_ransomware_detector.py -d /var/www --scan

# Monitoreo en tiempo real (detecta cifrado masivo)
python3 02_ransomware_detector.py -d /home --monitor -i 2

# Con reporte JSON
python3 02_ransomware_detector.py -d /data --scan -o ransomware_report.json
```
```
[CRÍTICO] ⚠ Nota de rescate: /data/!!!_readme_!!!.txt
[CRÍTICO] ⚠ Extensión ransomware: /data/photo.jpg.WNCRY
[ALTO]    Alta entropía (7.94 bits) — posible cifrado: /data/doc.pdf

[!] POSIBLE INFECCIÓN DE RANSOMWARE DETECTADA
    Acción: desconectar red, no apagar, contactar IR
```

---

### 🔑 03 · PKI Certificate Manager
Genera CA, certificados de servidor, inspecciona y audita X.509.

```bash
# Crear Certificate Authority
python3 03_pki_manager.py ca --cn "Mi-CA-Corp" --days 3650 --out pki/

# Generar cert de servidor firmado por la CA
python3 03_pki_manager.py server --cn "api.myapp.com" --ca-key pki/ca.key \
    --ca-cert pki/ca.crt --days 365 --sans www.myapp.com dev.myapp.com

# Inspeccionar certificado
python3 03_pki_manager.py inspect /etc/ssl/certs/myapp.crt
```
```
Sujeto  : CN=api.myapp.com,O=CyberToolkit
Expira  : 342 días
Key     : 2048 bits  Alg: SHA256
SANs    : ['api.myapp.com', 'www.myapp.com']
✓ Sin issues detectados
```

---

### 🎯 04 · Threat Intelligence Aggregator
Consulta IOCs (IP, hash, dominio) contra múltiples fuentes: DNSBL, URLhaus, ThreatFox, VirusTotal, AbuseIPDB.

```bash
# IOC gratuito (sin API key)
python3 04_threat_intel.py 45.33.32.156

# Con API keys
python3 04_threat_intel.py 45.33.32.156 --abuse-key KEY --vt-key KEY --shodan-key KEY

# Hash lookup
python3 04_threat_intel.py 5f4dcc3b5aa765d61d8327deb882cf99 --vt-key KEY

# Dominio
python3 04_threat_intel.py malware-domain.tk -o ioc_report.json
```
```
[AbuseIPDB]  abuse_score    : 97
             total_reports  : 2341
             country        : CN
[DNSBL]      En blacklist   : SÍ → zen.spamhaus.org, bl.spamcop.net
Veredicto: MALICIOSO
```

---

### 💬 05 · Secure Messaging E2E Simulator
Simula E2E con X25519 (ECDH) + AES-256-GCM. Demo de conversación cifrada.

```bash
# Demo completo de conversación cifrada
python3 05_secure_messaging.py demo

# Analizar seguridad de un protocolo de mensajería
python3 05_secure_messaging.py analyze signal
python3 05_secure_messaging.py analyze telegram
python3 05_secure_messaging.py analyze sms
```
```
[Alice → Bob]
Texto plano: El servidor tiene la IP 10.0.0.5
Cifrado    : Kx9mPzR+vL2/qN8w4jYs...
Descifrado : El servidor tiene la IP 10.0.0.5 ✓
Fingerprint: a3b4c5d6e7f80912

[signal]  ✓ E2E    ✓ Forward Secrecy    ✓ Open Source    Score: 10
[sms]     ✗ E2E    ✗ Forward Secrecy    Score: 2  ← Sin cifrado
```

---

### 🔬 06 · Digital Forensics Analyzer
Timeline de modificaciones, archivos ocultos, SUID, strings, reporte completo.

```bash
# Timeline de últimas modificaciones
python3 06_digital_forensics.py timeline -d /var/www

# Buscar archivos sospechosos (exe, ps1, bat...)
python3 06_digital_forensics.py suspicious -d /tmp

# Analizar archivo específico + strings
python3 06_digital_forensics.py file /tmp/suspicious.sh --strings

# Reporte forense completo
python3 06_digital_forensics.py report -d /home/user -o evidence.json
```
```
2024-01-15 03:17:42  /tmp/.hidden_backdoor.sh
2024-01-15 03:18:01  /var/www/html/shell.php

[SUID no estándar]  /tmp/.suid_backdoor
[Oculto]  /home/user/.bash_history_backup
```

---

### 🧅 07 · Dark Web / Tor OSINT
Verificar Tor, extraer .onion, metodología de investigación.

```bash
# Verificar si Tor está activo (necesita Tor Browser abierto)
python3 07_darkweb_osint.py tor-check

# Ver metodología de investigación OSINT en dark web
python3 07_darkweb_osint.py report

# Extraer .onion addresses de texto
python3 07_darkweb_osint.py extract texto_con_onions.txt

# Buscar keyword en paste sites
python3 07_darkweb_osint.py paste-search "leaked credentials"
```

---

### 💥 08 · DDoS Simulator & Detector
Simulación segura de ataques + detector por rate limiting (sin tráfico real).

```bash
# Simular y analizar patrones de ataque
python3 08_ddos_simulator.py simulate

# Explicar tipos de DDoS y mitigación
python3 08_ddos_simulator.py explain

# Modo detección en tiempo real (localhost)
python3 08_ddos_simulator.py detect -p 8888 -t 50
```
```
Total requests : 1649  Bloqueados: 300 (18.2%)
Tipos: syn_flood=500  http_flood=800  slowloris=150
[CRÍTICO] 203.0.113.1 — 500 req/s  → BLOQUEADO
[CRÍTICO] 198.51.100.1 — 80 req/s  → BLOQUEADO

[Slowloris] Mantiene conexiones abiertas sin completar request
  Mitigación: Timeout bajo, Nginx, conexiones por IP
```

---

### 🕵️ 09 · Rootkit Detector
Detección de procesos ocultos, módulos kernel, LD_PRELOAD, SUID, backdoors.

```bash
sudo python3 09_rootkit_detector.py -o rootkit_report.json
```
```
[*] Verificando: Procesos ocultos...
  [ALTO] En /proc pero no en ps: PID 1337 (sysmon_fake)

[*] Verificando: LD_PRELOAD...
  [CRÍTICO] LD_PRELOAD activo: /tmp/libhook.so

[*] Verificando: Puertos backdoor...
  [ALTO] Puerto 4444 abierto (Meterpreter default)

[*] Verificando: Persistencia...
  [ALTO] Comando wget en /etc/crontab
```

---

### 🤖 10 · AI Threat Predictor
Naive Bayes + Z-score para clasificar amenazas en tiempo real sin librerías ML externas.

```bash
# Demo con 5 eventos sintéticos
python3 10_ai_threat_predictor.py --demo

# Clasificar evento específico
python3 10_ai_threat_predictor.py --event port=22 failed_logins=high country=CN requests_per_min=150
```
```
[CRÍTICO] 45.33.32.156    brute_force          Conf: 71.4%  Anomaly: 7.47σ
[CRÍTICO] 203.0.113.5     sqli                 Conf: 85.2%  Anomaly: 12.3σ
[BAJO]    10.0.0.50        normal               Conf: 92.1%  Anomaly: 0.3σ
[CRÍTICO] 198.51.100.1    backdoor             Conf: 78.9%  Anomaly: 18.6σ
```

---

### 🔌 11 · API Security Tester
Auth bypass, IDOR, rate limiting, sensitive data, injection en REST APIs.

```bash
python3 11_api_security_tester.py -u https://api.target.com
python3 11_api_security_tester.py -u https://api.target.com -t "Bearer eyJ..." -o api_report.json
```
```
[CRÍTICO] AUTH_BYPASS: /api/admin accesible sin auth
[CRÍTICO] SQLI: SQL Injection en /api/search?q=
[ALTO]    POTENTIAL_IDOR: /api/users/3 accesible
[ALTO]    Sin rate limiting — vulnerable a brute force
[MEDIO]   SENSITIVE_DISCLOSURE: /api/debug expone config
```

---

### 🔍 12 · Vulnerability Scanner Pro
Fingerprint de servicios + mapeo automático a CVEs conocidos.

```bash
python3 12_vuln_scanner_pro.py -t 192.168.1.100 -p common -o cve_report.json
python3 12_vuln_scanner_pro.py -t 10.0.0.50 -p 21,22,80,443,3306
```
```
[21]  vsftpd  2.3.4
  [CRÍTICO] CVE-2011-2523: Backdoor in vsftpd 2.3.4 (smile exploit)

[80]  Apache  2.4.49
  [CRÍTICO] CVE-2021-41773: Path traversal and RCE (exploited in wild)
  [CRÍTICO] CVE-2021-42013: Path traversal bypass

[6379] Redis  any
  [CRÍTICO] CVE-2022-0543: Lua sandbox escape — RCE
```

---

### 🏠 13 · Smart Home / IoT Security
Scan de dispositivos IoT: Telnet, MQTT sin auth, UPnP, credenciales por defecto.

```bash
python3 13_smart_home_security.py -t 192.168.1.100
python3 13_smart_home_security.py --demo
```
```
IP     : 192.168.1.100
Device : Hikvision IP Camera
Puertos abiertos:
     80   HTTP
    554   RTSP
     23   Telnet (CRÍTICO)   ← SIN CIFRADO
   1883   MQTT

[CRÍTICO] Telnet expuesto sin cifrado
[CRÍTICO] MQTT sin autenticación
[CRÍTICO] Credenciales por defecto: admin:12345
```

---

### 🐳 14 · Container Security Scanner
Audita Docker containers y Kubernetes pods por configuraciones inseguras.

```bash
# Escanear contenedores Docker corriendo
sudo python3 14_container_security.py docker

# Analizar Dockerfile
python3 14_container_security.py dockerfile ./Dockerfile

# Auditar pods Kubernetes
python3 14_container_security.py k8s
```
```
[CRÍTICO] Container 'api-server' running PRIVILEGED
[CRÍTICO] Dangerous capability: SYS_ADMIN in 'debug-pod'
[CRÍTICO] Sensitive mount: /var/run/docker.sock in 'ci-runner'
[ALTO]    Container 'webapp' running as root
[MEDIO]   Port 3306/tcp bound to 0.0.0.0 in 'mysql'
```

---

### ⛓️ 15 · Blockchain Security Analyzer
Detecta vulnerabilidades en contratos Solidity + validación de wallets.

```bash
# Demo análisis de contrato vulnerable
python3 15_blockchain_security.py demo

# Analizar contrato .sol
python3 15_blockchain_security.py contract MyContract.sol -o report.json

# Validar dirección de wallet
python3 15_blockchain_security.py wallet 0x742d35Cc6634C0532925a3b8D4C9D5e6A4dF1e7
```
```
[CRÍTICO] Line 15: Potential reentrancy — no ReentrancyGuard
[CRÍTICO] Line 23: tx.origin auth bypass — use msg.sender
[CRÍTICO] Line 31: selfdestruct — contract can be destroyed
[ALTO]    Line 38: Weak randomness via block hash
[ALTO]    Old Solidity version — use 0.8+
```

---

### 🏭 16 · SCADA / ICS Security Scanner
Detecta protocolos industriales expuestos: Modbus, DNP3, Siemens S7, BACnet.

```bash
# Escanear objetivo ICS
python3 16_scada_security.py scan -t 192.168.1.200 -o ics_report.json

# Explicar riesgos ICS con casos reales
python3 16_scada_security.py explain
```
```
[CRÍTICO] Modbus TCP    → Sin autenticación — acceso directo a PLCs
[CRÍTICO] Siemens S7    → PLC Siemens detectado
[ALTO]    BACnet        → Automatización de edificios expuesta

Casos reales:
  Stuxnet 2010    — centrifugas nucleares iraníes
  Ukraine 2015    — BlackEnergy apagó red eléctrica
  Target 2013     — HVAC breach → 40M tarjetas
```

---

### 🎯 17 · Cyber Range Scenario Generator
Genera escenarios CTF completos con flags, objetivos, hints y diagramas de red.

```bash
# Listar templates disponibles
python3 17_cyber_range_generator.py list

# Generar escenario web
python3 17_cyber_range_generator.py scenario -t web_exploitation --team "Red Team" -o ctf.json

# Generar diagrama de red de laboratorio
python3 17_cyber_range_generator.py network -n 8 -o lab_network.json
```
```
Escenario  : Web Application Attack Chain
Dificultad : Intermediate
Tiempo     : 2h

Objetivo 1 → Enumerate endpoints
  Flag: CTF{enum3r4t3_endp01nts_a3b4c5d6}  [100 pts]
Objetivo 2 → Exploit SQL injection
  Flag: CTF{sql_1nj3ct10n_c7d8e9f0}        [100 pts]
Herramientas: sqlmap, Burp Suite, curl
```

---

### ⚛️ 18 · Quantum Cryptography
Simula BB84 QKD, algoritmo de Shor, comparativa post-quantum, ataque HNDL.

```bash
# Simular BB84 con espionaje
python3 18_quantum_crypto.py bb84 --eve

# Comparar algoritmos clásicos vs post-quantum
python3 18_quantum_crypto.py pqc

# Explicar Harvest Now Decrypt Later
python3 18_quantum_crypto.py hndl
```
```
BB84 (con Eve espionando):
  Alice key : 11101001010000001010
  Bob key   : 11001001010100001010
  QBER      : 23.5% (threshold: 11%)
  Eve detect: True → Canal comprometido, descartar clave

PQC Comparison:
  RSA-2048         ✗ Quantum-unsafe   → Legacy (Shor's en O(n³))
  CRYSTALS-Kyber   ✓ Quantum-safe     → NIST Standard 2024
  CRYSTALS-Dilithium✓ Quantum-safe    → NIST Standard 2024
```

---

### ⏱️ 19 · Side Channel Attack Simulator
Timing attack demo + prueba vulnerable vs constant-time comparison.

```bash
# Demo ataque de timing (recuperar password char a char)
python3 19_side_channel.py timing

# Comparar función vulnerable vs constant-time
python3 19_side_channel.py compare

# Explicar tipos de ataques de canal lateral
python3 19_side_channel.py explain
```
```
Pos 0: ✓ Guessed='s' Correct='s'  Time=1847ns
Pos 1: ✓ Guessed='3' Correct='3'  Time=1923ns
Pos 2: ✗ Guessed='k' Correct='c'  Time=1801ns

Vulnerable:     1920 ns  ← timing leak (early exit)
Constant-time:  1850 ns  ← no leak (hmac.compare_digest)
```

---

### 🎭 20 · Malware Obfuscation Analyzer
Detecta y decodifica Base64, hex, URL encoding, PowerShell encoded, entropía.

```bash
python3 20_obfuscation_analyzer.py -f suspicious_script.ps1
python3 20_obfuscation_analyzer.py --demo
python3 20_obfuscation_analyzer.py -f malware.py -o decoded_report.json
```
```
[CRÍTICO] PS_ENCODED_CMD  : $client=New-Object System.Net.Sockets.TCPClient...
[CRÍTICO] BASE64_PAYLOAD  : import os; os.system('whoami')
[ALTO]    HEX_ENCODED     : powershell
[ALTO]    DANGEROUS_FUNCTION: os.system, shell=True, eval(
[MEDIO]   HIGH_ENTROPY    : 5.87 bits → posible cifrado/compresión
```

---

## 🔗 Flujo de pentesting avanzado

```
FASE 1 — RECONOCIMIENTO ESPECIALIZADO
  04_threat_intel    → IOC check de IPs/dominios objetivo
  07_darkweb_osint   → Búsqueda de credenciales filtradas
  12_vuln_scanner_pro→ CVE mapping de servicios encontrados

FASE 2 — ANÁLISIS DE SUPERFICIE
  11_api_security    → Auditar APIs expuestas
  13_smart_home      → Escanear dispositivos IoT en red
  16_scada_security  → Verificar protocolos industriales

FASE 3 — AUDITORÍA DE SEGURIDAD
  01_zero_trust      → Evaluar postura defensiva
  14_container_sec   → Auditar contenedores y K8s
  09_rootkit_detector→ Verificar integridad del sistema

FASE 4 — ANÁLISIS FORENSE
  06_digital_forensics → Timeline y artefactos
  20_obfuscation       → Analizar malware encontrado
  10_ai_predictor      → Clasificar eventos del SIEM

FASE 5 — EDUCACIÓN Y DEMO
  17_cyber_range       → Generar lab para el equipo
  18_quantum_crypto    → Demostrar riesgos futuros
  19_side_channel      → Training en vulnerabilidades avanzadas
```

---

## 📦 Dependencias

```bash
pip install -r requirements.txt
```

| Librería | Herramientas | Propósito |
|----------|-------------|-----------|
| `colorama` | Todas | Colores en terminal |
| `requests` | 04,07,11,13 | HTTP requests |
| `cryptography` | 03,05 | PKI + AES-GCM |
| `paramiko` | 04 (SSH) | SSH connections |
| `dnspython` | 04 | DNS lookups |

---

## 📁 Estructura del repositorio

```
cyber-toolkit-v3/
├── 01_zero_trust_model.py
├── 02_ransomware_detector.py
├── 03_pki_manager.py
├── 04_threat_intel.py
├── 05_secure_messaging.py
├── 06_digital_forensics.py
├── 07_darkweb_osint.py
├── 08_ddos_simulator.py
├── 09_rootkit_detector.py
├── 10_ai_threat_predictor.py
├── 11_api_security_tester.py
├── 12_vuln_scanner_pro.py
├── 13_smart_home_security.py
├── 14_container_security.py
├── 15_blockchain_security.py
├── 16_scada_security.py
├── 17_cyber_range_generator.py
├── 18_quantum_crypto.py
├── 19_side_channel.py
├── 20_obfuscation_analyzer.py
└── requirements.txt
```

---

## 🧪 Entornos recomendados

```
✔ Kali Linux / Parrot OS
✔ Docker con imágenes vulnerables (DVWA, Metasploitable)
✔ VMware / VirtualBox lab aislado
✔ HackTheBox / TryHackMe
✔ Hardware IoT propio (Raspberry Pi, routers viejos)
✘ NUNCA en sistemas productivos sin autorización
```

---

## ⚠️ Disclaimer

> Toolkit desarrollado para **investigación, educación y pentesting autorizado**.  
> Úsalo únicamente en entornos propios o con autorización **escrita** del propietario.  
> El autor no se responsabiliza por uso indebido. Actúa siempre dentro del marco legal.

---

<div align="center">

**Kaled Corcho** — [github.com/kaleth4](https://github.com/kaleth4)  
`Cybersecurity Analyst Jr.` · `Red Team` · `Blue Team` · `ICS/IoT` · `Python Security`

📦 **Vol.1** `cyber-toolkit` · **Vol.2** `cyber-toolkit-v2` · **Vol.3** `cyber-toolkit-v3`

⭐ Si este repo te fue útil, deja una estrella

</div>
