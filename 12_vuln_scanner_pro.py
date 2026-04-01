#!/usr/bin/env python3
"""12 · VULNERABILITY SCANNER PRO — CVE-based service vulnerability assessment"""

import socket, subprocess, re, json, argparse, sys, concurrent.futures
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🔍 VULN SCANNER PRO  v1.0           ║\n║  Service fingerprint + CVE mapping   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

# Service → Version pattern → Known CVEs
CVE_DATABASE = {
    "OpenSSH": {
        "8.0": [("CVE-2020-14145","MEDIO","Observable discrepancy in auth timing")],
        "7.4": [("CVE-2018-15473","MEDIO","Username enumeration via timing attack"),
                ("CVE-2016-6515","ALTO", "Denial of service via crafted packet")],
        "6.x": [("CVE-2016-0777","ALTO","Information leak via UseRoaming"),
                ("CVE-2014-1692","ALTO","Hash collision via J-PAKE")],
    },
    "Apache": {
        "2.4.49": [("CVE-2021-41773","CRÍTICO","Path traversal and RCE (exploited in wild)"),
                    ("CVE-2021-42013","CRÍTICO","Path traversal bypass")],
        "2.4.50": [("CVE-2021-42013","CRÍTICO","Path traversal bypass")],
        "2.2.x":  [("CVE-2017-7679","CRÍTICO","Buffer overflow in mod_mime"),
                    ("CVE-2017-7668","ALTO",   "Buffer overread ap_find_token()")],
    },
    "nginx": {
        "1.14": [("CVE-2019-9511","ALTO","HTTP/2 DoS via HEADERS flooding"),
                  ("CVE-2019-9513","ALTO","HTTP/2 DoS via priority manipulation")],
        "1.0.x": [("CVE-2013-2028","CRÍTICO","Stack buffer overflow in nginx"),],
    },
    "vsftpd": {
        "2.3.4": [("CVE-2011-2523","CRÍTICO","Backdoor in vsftpd 2.3.4 (smile exploit)")],
    },
    "ProFTPD": {
        "1.3.5": [("CVE-2015-3306","CRÍTICO","Remote code execution via mod_copy")],
    },
    "MySQL": {
        "5.x":   [("CVE-2016-6662","CRÍTICO","Privilege escalation via config injection")],
    },
    "Redis": {
        "any":   [("CVE-2022-0543","CRÍTICO","Lua sandbox escape — RCE"),
                   ("CVE-2015-8080","CRÍTICO","Integer overflow in Lua scripting")],
    },
    "Samba": {
        "4.x":   [("CVE-2017-7494","CRÍTICO","SambaCry — RCE via writable share"),
                   ("CVE-2017-11103","ALTO",   "Heimdal KDC null pointer dereference")],
    },
}

def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    probes = {
        22:  b"",
        21:  b"",
        80:  b"HEAD / HTTP/1.0\r\n\r\n",
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        25:  b"EHLO test\r\n",
        110: b"",
        143: b"",
    }
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            probe = probes.get(port, b"")
            if probe: s.sendall(probe)
            return s.recv(2048).decode(errors="replace").strip()
    except: return ""

def fingerprint_service(banner: str, port: int) -> dict:
    banner_lower = banner.lower()
    service = "Unknown"; version = "unknown"

    patterns = [
        ("OpenSSH", r"ssh-\d+\.\d+-openssh[_\s](\S+)",        banner_lower),
        ("Apache",  r"apache/(\d+\.\d+\.\d+)",                  banner_lower),
        ("nginx",   r"nginx/(\d+\.\d+\.\d+)",                   banner_lower),
        ("vsftpd",  r"vsftpd\s+(\d+\.\d+\.\d+)",               banner_lower),
        ("ProFTPD", r"proftpd\s+(\d+\.\d+\.\d+)",               banner_lower),
        ("MySQL",   r"(\d+\.\d+\.\d+)-mysql",                    banner_lower),
        ("Redis",   r"redis_version:(\S+)",                      banner_lower),
        ("Samba",   r"samba[/ ](\d+\.\d+)",                      banner_lower),
        ("IIS",     r"microsoft-iis/(\d+\.\d+)",                 banner_lower),
        ("Tomcat",  r"apache[- ]tomcat/(\d+\.\d+\.\d+)",        banner_lower),
    ]

    for svc, pattern, text in patterns:
        m = re.search(pattern, text)
        if m:
            service = svc
            version = m.group(1)
            break

    return {"service": service, "version": version, "banner": banner[:150]}

def lookup_cves(service: str, version: str) -> list:
    cves = []
    service_db = CVE_DATABASE.get(service, {})
    # Exact match
    if version in service_db:
        cves.extend(service_db[version])
    # Partial match (e.g. "2.4.49" matches "2.4")
    for ver_key, cve_list in service_db.items():
        if ver_key != "any" and version.startswith(ver_key[:3]):
            cves.extend(cve_list)
    # "any" version applies to all
    if "any" in service_db:
        cves.extend(service_db["any"])
    return list({c[0]:c for c in cves}.values())  # deduplicate by CVE ID

def scan_and_analyze(ip: str, ports: list, timeout: float = 2.0) -> list:
    results = []
    def scan_port(port):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                banner = grab_banner(ip, port, timeout)
                fp     = fingerprint_service(banner, port)
                cves   = lookup_cves(fp["service"], fp["version"])
                return {"port":port, "ip":ip, **fp, "cves":cves}
        except: return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(scan_port, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r: results.append(r)

    return sorted(results, key=lambda x: x["port"])

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Vulnerability Scanner Pro")
    parser.add_argument("-t","--target",  required=True)
    parser.add_argument("-p","--ports",   default="common")
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    COMMON = [21,22,23,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,27017,9200]
    ports  = COMMON if args.ports=="common" else [int(p) for p in args.ports.split(",")]

    try:
        ip = socket.gethostbyname(args.target)
    except:
        print(f"{Fore.RED}[✗] No se pudo resolver: {args.target}"); sys.exit(1)

    print(f"\n{Fore.CYAN}[*] Target: {ip}  Ports: {len(ports)}\n")
    results = scan_and_analyze(ip, ports)

    total_cves = 0
    for r in results:
        cve_c = Fore.RED if r["cves"] else Fore.GREEN
        print(f"\n  {Fore.GREEN}[{r['port']}]{Style.RESET_ALL} "
              f"{Fore.YELLOW}{r['service']}{Style.RESET_ALL} "
              f"{Fore.CYAN}{r['version']}{Style.RESET_ALL}")
        if r["banner"]:
            print(f"  Banner: {Fore.GRAY}{r['banner'][:80]}{Style.RESET_ALL}")
        if r["cves"]:
            print(f"  {Fore.RED}CVEs conocidos:{Style.RESET_ALL}")
            for cve_id, level, desc in r["cves"]:
                c = Fore.RED if level=="CRÍTICO" else Fore.YELLOW
                print(f"    {c}[{level}]{Style.RESET_ALL} {cve_id}: {desc}")
                total_cves += 1

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.CYAN}Puertos abiertos: {len(results)}  CVEs: {total_cves}")
    if args.output:
        with open(args.output,"w") as f: json.dump(results, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
