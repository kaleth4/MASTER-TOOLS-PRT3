#!/usr/bin/env python3
"""07 · DARK WEB SCRAPER SIMULATOR — Tor network OSINT (educational)"""

import requests, argparse, json, re, sys, time
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🧅 TOR/DARK WEB OSINT  v1.0         ║\n║  Educational simulation + Tor check  ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

ONION_PATTERNS = [
    r"[a-z2-7]{56}\.onion",   # v3 onion
    r"[a-z2-7]{16}\.onion",   # v2 onion (deprecated)
]

KNOWN_ONIONS_LEGIT = {
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion": "DuckDuckGo (search)",
    "www.nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion": "NYTimes (journalism)",
    "facebookwkhpilnemxj7asber7cyec5v2zLost.onion": "Facebook (legacy)",
    "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion": "ProtonMail",
}

def check_tor_connection() -> dict:
    """Check if Tor is running and accessible."""
    proxies = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}
    try:
        r = requests.get("https://check.torproject.org/api/ip",
                          proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {"tor_running":True, "is_tor":data.get("IsTor",False),
                    "ip":data.get("IP","?")}
    except Exception as e:
        pass
    return {"tor_running":False, "note":"Tor no disponible en localhost:9050"}

def extract_onions_from_text(text: str) -> list:
    found = []
    for pattern in ONION_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        found.extend(matches)
    return list(set(found))

def classify_onion(onion: str) -> dict:
    version = "v3" if len(onion.replace(".onion","")) == 56 else "v2 (deprecated)"
    known   = KNOWN_ONIONS_LEGIT.get(onion, "Desconocido")
    return {"onion":onion, "version":version, "known_service":known}

def simulate_osint_report() -> dict:
    """Generate a simulated dark web OSINT report for educational purposes."""
    return {
        "disclaimer": "SIMULACIÓN EDUCATIVA — No datos reales",
        "methodology": [
            "1. Conectar a red Tor (tor.exe o Tor Browser)",
            "2. Usar índices .onion: Ahmia.fi, Torch, NotEvil",
            "3. Extraer .onion addresses de resultados",
            "4. Verificar con OSINT: Darkside, OnionScan",
            "5. Documentar sin acceder a contenido ilegal",
        ],
        "legal_notice": "Acceder a contenido ilegal en dark web es un delito. "
                        "Solo usar para investigación autorizada.",
        "legitimate_uses": [
            "Periodismo en países con censura",
            "Comunicación segura de whistleblowers",
            "Investigación de amenazas (CTI)",
            "Monitoreo de credenciales filtradas",
            "Acceso a servicios de privacidad (ProtonMail, DuckDuckGo)",
        ],
        "tools_for_research": [
            "Ahmia.fi — índice .onion de acceso desde clearnet",
            "OnionScan — scanner de servicios .onion",
            "DarkOwl — plataforma comercial de inteligencia",
            "Maltego — análisis de grafos OSINT",
            "IntelX — motor de búsqueda de datos filtrados",
        ],
    }

def check_paste_sites(keyword: str) -> list:
    """Search public paste sites for leaked data (clearnet only)."""
    results = []
    sites = [
        f"https://pastebin.com/search?q={keyword}",
        f"https://ghostbin.com/search?q={keyword}",
    ]
    for site in sites:
        try:
            r = requests.get(site, timeout=8, verify=False,
                              headers={"User-Agent":"Mozilla/5.0"})
            if r.status_code == 200:
                results.append({"site":site,"status":r.status_code,
                                  "note":"Buscar manualmente en el browser"})
        except: pass
    return results

def main():
    print(BANNER)
    print(f"{Fore.RED}⚠  HERRAMIENTA EDUCATIVA — Solo para investigación autorizada{Style.RESET_ALL}\n")

    parser = argparse.ArgumentParser(description="Tor/Dark Web OSINT Simulator")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("tor-check",  help="Verificar conexión Tor")
    sub.add_parser("report",     help="Reporte metodología OSINT dark web")
    ext_p = sub.add_parser("extract", help="Extraer .onion de texto/archivo")
    ext_p.add_argument("input", help="Texto o ruta de archivo")
    pas_p = sub.add_parser("paste-search", help="Buscar en paste sites")
    pas_p.add_argument("keyword")
    args = parser.parse_args()

    if args.cmd == "tor-check":
        print(f"{Fore.CYAN}[*] Verificando conexión Tor...\n")
        r = check_tor_connection()
        if r.get("tor_running"):
            print(f"  {Fore.GREEN}[✓] Tor conectado")
            print(f"  IP pública Tor: {r.get('ip','?')}")
            print(f"  Is Tor: {r.get('is_tor')}")
        else:
            print(f"  {Fore.YELLOW}[!] Tor no disponible")
            print(f"  Para activar: instala Tor Browser o tor daemon")
            print(f"  Puerto: socks5h://127.0.0.1:9050")

    elif args.cmd == "report":
        r = simulate_osint_report()
        print(f"\n{Fore.CYAN}[*] Metodología OSINT Dark Web\n")
        for section, content in r.items():
            if section == "disclaimer":
                print(f"  {Fore.YELLOW}{content}{Style.RESET_ALL}\n")
                continue
            print(f"  {Fore.CYAN}{section.replace('_',' ').upper()}:{Style.RESET_ALL}")
            if isinstance(content, list):
                for item in content:
                    print(f"    • {item}")
            else:
                print(f"    {content}")
            print()

    elif args.cmd == "extract":
        text = args.input
        if os.path.isfile(args.input):
            with open(args.input) as f:
                text = f.read()
        onions = extract_onions_from_text(text)
        print(f"\n{Fore.CYAN}[*] .onion addresses encontradas: {len(onions)}\n")
        for o in onions:
            info = classify_onion(o)
            print(f"  {Fore.YELLOW}{info['onion']}{Style.RESET_ALL}")
            print(f"    Version: {info['version']}")
            print(f"    Servicio: {info['known_service']}\n")

    elif args.cmd == "paste-search":
        print(f"{Fore.CYAN}[*] Buscando '{args.keyword}' en paste sites...")
        results = check_paste_sites(args.keyword)
        for r in results:
            print(f"  {r['site']} — {r.get('note','')}")

    else:
        print("  Comandos: tor-check, report, extract, paste-search")
        print("  Ejemplo: python3 07_darkweb_osint.py report")

if __name__ == "__main__":
    import os
    main()
