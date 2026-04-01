#!/usr/bin/env python3
"""04 · THREAT INTELLIGENCE AGGREGATOR — Collect IOCs from multiple sources"""

import requests, argparse, json, re, sys
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🎯 THREAT INTEL AGGREGATOR  v1.0   ║\n║  IOC lookup · IP · Hash · Domain    ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def check_abuseipdb(ip: str, api_key: str = None) -> dict:
    if not api_key:
        return {"source":"AbuseIPDB","error":"No API key — get free key at abuseipdb.com"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                          params={"ipAddress":ip,"maxAgeInDays":90},
                          headers={"Key":api_key,"Accept":"application/json"},
                          timeout=8)
        d = r.json().get("data",{})
        return {"source":"AbuseIPDB","ip":ip,
                "abuse_score":d.get("abuseConfidenceScore",0),
                "total_reports":d.get("totalReports",0),
                "country":d.get("countryCode","?"),
                "isp":d.get("isp","?")}
    except Exception as e:
        return {"source":"AbuseIPDB","error":str(e)}

def check_virustotal_ip(ip: str, api_key: str = None) -> dict:
    if not api_key:
        return {"source":"VirusTotal","error":"No API key — get free key at virustotal.com"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                          headers={"x-apikey":api_key}, timeout=10)
        if r.status_code == 200:
            stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"source":"VirusTotal","ip":ip,
                    "malicious":stats.get("malicious",0),
                    "suspicious":stats.get("suspicious",0),
                    "harmless":stats.get("harmless",0)}
        return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source":"VirusTotal","error":str(e)}

def check_virustotal_hash(file_hash: str, api_key: str = None) -> dict:
    if not api_key:
        return {"source":"VirusTotal","error":"No API key"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                          headers={"x-apikey":api_key}, timeout=10)
        if r.status_code == 200:
            attr  = r.json().get("data",{}).get("attributes",{})
            stats = attr.get("last_analysis_stats",{})
            return {"source":"VirusTotal","hash":file_hash,
                    "name":attr.get("meaningful_name","?"),
                    "malicious":stats.get("malicious",0),
                    "total_engines":sum(stats.values())}
        if r.status_code == 404:
            return {"source":"VirusTotal","hash":file_hash,"found":False}
        return {"source":"VirusTotal","error":f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source":"VirusTotal","error":str(e)}

def check_shodan_ip(ip: str, api_key: str = None) -> dict:
    if not api_key:
        return {"source":"Shodan","error":"No API key — get at shodan.io"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {"source":"Shodan","ip":ip,
                    "ports":d.get("ports",[])[:10],
                    "org":d.get("org","?"),
                    "country":d.get("country_name","?"),
                    "vulns":list(d.get("vulns",{}).keys())[:5]}
        return {"source":"Shodan","error":f"HTTP {r.status_code}"}
    except Exception as e:
        return {"source":"Shodan","error":str(e)}

def check_free_sources(ioc: str, ioc_type: str) -> list:
    """Free checks that don't require API keys."""
    results = []
    # Basic reputation check via DNS blacklists (for IPs)
    if ioc_type == "ip":
        dnsbls = ["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"]
        reversed_ip = ".".join(reversed(ioc.split(".")))
        import socket
        listed = []
        for bl in dnsbls:
            try:
                socket.gethostbyname(f"{reversed_ip}.{bl}")
                listed.append(bl)
            except: pass
        results.append({"source":"DNSBL","ip":ioc,"blacklists":listed,
                         "listed": len(listed)>0})

    # URLhaus for domains/URLs
    if ioc_type in ("domain","url"):
        try:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                               data={"host":ioc}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                results.append({"source":"URLhaus","ioc":ioc,
                                  "status":d.get("query_status","?"),
                                  "urls_count":len(d.get("urls",[]))})
        except: pass

    # ThreatFox for hashes
    if ioc_type == "hash":
        try:
            r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                               json={"query":"search_ioc","search_term":ioc}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                results.append({"source":"ThreatFox","hash":ioc,
                                  "status":d.get("query_status","?"),
                                  "data":d.get("data",[])[:3]})
        except: pass
    return results

def detect_ioc_type(ioc: str) -> str:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc): return "ip"
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):  return "hash"  # MD5
    if re.match(r"^[0-9a-fA-F]{40}$", ioc):  return "hash"  # SHA1
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):  return "hash"  # SHA256
    if re.match(r"^https?://", ioc):          return "url"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc): return "domain"
    return "unknown"

def print_result(r: dict):
    source = r.get("source","?")
    if "error" in r:
        print(f"  {Fore.GRAY}[{source}] {r['error']}{Style.RESET_ALL}")
        return

    print(f"\n  {Fore.CYAN}[{source}]{Style.RESET_ALL}")
    for k,v in r.items():
        if k == "source": continue
        if isinstance(v, list) and not v: continue
        val_str = str(v)
        if k in ("malicious","abuse_score") and isinstance(v, (int,float)) and v > 0:
            print(f"    {Fore.RED}{k:<20}: {v}{Style.RESET_ALL}")
        elif k == "listed" and v:
            print(f"    {Fore.RED}{'En blacklist':<20}: SÍ{Style.RESET_ALL}")
        else:
            print(f"    {k:<20}: {val_str[:80]}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator")
    parser.add_argument("ioc",           help="IOC: IP, hash, dominio o URL")
    parser.add_argument("--vt-key",      default=None, help="VirusTotal API Key")
    parser.add_argument("--abuse-key",   default=None, help="AbuseIPDB API Key")
    parser.add_argument("--shodan-key",  default=None, help="Shodan API Key")
    parser.add_argument("-o","--output", default=None)
    args = parser.parse_args()

    ioc_type = detect_ioc_type(args.ioc)
    print(f"\n{Fore.CYAN}[*] IOC     : {args.ioc}")
    print(f"{Fore.CYAN}[*] Tipo    : {ioc_type.upper()}")
    print(f"{Fore.GRAY}{'─'*44}\n")

    all_results = []

    # Free sources
    free = check_free_sources(args.ioc, ioc_type)
    for r in free:
        print_result(r)
        all_results.append(r)

    # API sources
    if ioc_type == "ip":
        r = check_abuseipdb(args.ioc, args.abuse_key)
        print_result(r); all_results.append(r)
        r = check_virustotal_ip(args.ioc, args.vt_key)
        print_result(r); all_results.append(r)
        r = check_shodan_ip(args.ioc, args.shodan_key)
        print_result(r); all_results.append(r)

    elif ioc_type == "hash":
        r = check_virustotal_hash(args.ioc, args.vt_key)
        print_result(r); all_results.append(r)

    # Summary
    malicious_count = sum(
        r.get("malicious",0) + (1 if r.get("listed") else 0) + (1 if r.get("abuse_score",0)>25 else 0)
        for r in all_results
    )
    print(f"\n{Fore.GRAY}{'─'*44}")
    verdict = f"{Fore.RED}MALICIOSO" if malicious_count > 0 else f"{Fore.GREEN}LIMPIO (en fuentes verificadas)"
    print(f"  Veredicto: {verdict}{Style.RESET_ALL}")

    if args.output:
        with open(args.output,"w") as f:
            json.dump({"ioc":args.ioc,"type":ioc_type,"results":all_results}, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
