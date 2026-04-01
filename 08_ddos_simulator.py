#!/usr/bin/env python3
"""08 · DDoS SIMULATOR — Safe lab simulation & detection (no real attack)"""

import socket, threading, time, argparse, json, random, sys
from datetime import datetime
from collections import defaultdict, deque
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  💥 DDoS SIMULATOR  v1.0             ║\n║  Safe lab only — detect & mitigate   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

# ── DDoS Detection Engine ────────────────────────────────────────
class DDoSDetector:
    """Rate-based DDoS detector using sliding window."""
    def __init__(self, threshold_rps: int = 100, window_secs: int = 10):
        self.threshold  = threshold_rps
        self.window     = window_secs
        self.ip_windows = defaultdict(deque)
        self.blocked    = set()
        self.alerts     = []
        self.lock       = threading.Lock()

    def record_request(self, ip: str, ts: float = None) -> bool:
        if ts is None: ts = time.time()
        with self.lock:
            if ip in self.blocked:
                return False  # blocked
            window = self.ip_windows[ip]
            # Remove old entries
            cutoff = ts - self.window
            while window and window[0] < cutoff:
                window.popleft()
            window.append(ts)
            rps = len(window) / self.window
            if rps > self.threshold:
                self.blocked.add(ip)
                alert = {"ts":datetime.now().isoformat(),"ip":ip,
                          "rps":round(rps,1),"level":"CRÍTICO"}
                self.alerts.append(alert)
                return False
        return True

    def get_stats(self) -> dict:
        with self.lock:
            return {
                "total_ips":    len(self.ip_windows),
                "blocked_ips":  len(self.blocked),
                "alerts":       len(self.alerts),
                "top_ips":      sorted(
                    [(ip, len(w)) for ip,w in self.ip_windows.items()],
                    key=lambda x: x[1], reverse=True
                )[:10],
            }

# ── Attack Pattern Simulator (safe, no real traffic) ────────────
def simulate_attack_patterns() -> list:
    """Generate synthetic attack data for educational analysis."""
    patterns = []
    now = time.time()

    # Normal traffic baseline
    normal_ips = [f"10.0.1.{i}" for i in range(1,20)]
    for ip in normal_ips:
        for _ in range(random.randint(5,15)):
            patterns.append({"ip":ip,"ts":now - random.uniform(0,10),"type":"normal"})

    # SYN flood simulation
    attacker_ip = "203.0.113.1"  # RFC 5737 TEST-NET
    for _ in range(500):
        patterns.append({"ip":attacker_ip,"ts":now - random.uniform(0,5),"type":"syn_flood"})

    # HTTP flood
    http_ips = [f"198.51.100.{i}" for i in range(1,11)]  # RFC 5737
    for ip in http_ips:
        for _ in range(80):
            patterns.append({"ip":ip,"ts":now - random.uniform(0,8),"type":"http_flood"})

    # Slowloris
    slow_ips = [f"192.0.2.{i}" for i in range(1,6)]  # RFC 5737
    for ip in slow_ips:
        for _ in range(30):
            patterns.append({"ip":ip,"ts":now - random.uniform(0,10),"type":"slowloris"})

    return patterns

def analyze_attack(patterns: list) -> dict:
    detector = DDoSDetector(threshold_rps=20, window_secs=10)
    allowed  = blocked = 0
    by_type  = defaultdict(int)

    for req in patterns:
        result = detector.record_request(req["ip"], req["ts"])
        by_type[req["type"]] += 1
        if result: allowed += 1
        else:       blocked += 1

    stats = detector.get_stats()
    return {
        "total_requests": len(patterns),
        "allowed":        allowed,
        "blocked":        blocked,
        "block_rate":     round(blocked/len(patterns)*100,1),
        "attack_types":   dict(by_type),
        "top_attackers":  stats["top_ips"][:5],
        "alerts":         detector.alerts[:10],
    }

def explain_attack_types() -> dict:
    return {
        "SYN Flood": {
            "desc":"Envía miles de paquetes TCP SYN sin completar el handshake",
            "impact":"Agota la tabla de conexiones del servidor",
            "detection":"Rate de SYN sin ACK correspondiente",
            "mitigation":"SYN cookies, rate limiting, firewall stateful",
        },
        "HTTP Flood": {
            "desc":"Solicitudes HTTP GET/POST legítimas en volumen masivo",
            "impact":"Agota CPU y memoria del servidor web",
            "detection":"Requests por IP/segundo, User-Agent analysis",
            "mitigation":"CAPTCHA, rate limiting, CDN con WAF",
        },
        "Slowloris": {
            "desc":"Mantiene conexiones abiertas enviando headers incompletos",
            "impact":"Agota el límite de conexiones simultáneas",
            "detection":"Conexiones de larga duración sin completar request",
            "mitigation":"Timeout bajo, límite conexiones por IP, Nginx",
        },
        "UDP Flood": {
            "desc":"Inunda con paquetes UDP a puertos aleatorios",
            "impact":"Saturación de ancho de banda",
            "detection":"Volumen UDP anormal, IP spoofing",
            "mitigation":"Filtrado upstream, black hole routing",
        },
        "DNS Amplification": {
            "desc":"Usa servidores DNS como amplificadores (factor 50x)",
            "impact":"Amplificación masiva de tráfico hacia víctima",
            "detection":"Respuestas DNS sin query correspondiente",
            "mitigation":"Response Rate Limiting en DNS, BCP38",
        },
    }

def main():
    print(BANNER)
    print(f"{Fore.RED}⚠  SOLO USO EN LAB CONTROLADO — No usar contra sistemas reales{Style.RESET_ALL}\n")
    parser = argparse.ArgumentParser(description="DDoS Simulator & Detector")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("simulate",  help="Simular ataque y detectar")
    sub.add_parser("explain",   help="Explicar tipos de DDoS y mitigación")
    det_p = sub.add_parser("detect", help="Modo detección en tiempo real (localhost)")
    det_p.add_argument("-p","--port", type=int, default=8888)
    det_p.add_argument("-t","--threshold", type=int, default=50)
    args = parser.parse_args()

    if args.cmd == "explain":
        attacks = explain_attack_types()
        for name, info in attacks.items():
            print(f"\n  {Fore.RED}[{name}]{Style.RESET_ALL}")
            for k,v in info.items():
                print(f"    {Fore.CYAN}{k:<14}{Style.RESET_ALL}: {v}")

    elif args.cmd == "detect":
        detector = DDoSDetector(threshold_rps=args.threshold)
        print(f"{Fore.CYAN}[*] Detector activo en localhost:{args.port}")
        print(f"{Fore.CYAN}[*] Threshold: {args.threshold} req/s (Ctrl+C para detener)\n")
        try:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", args.port))
            srv.listen(100)
            while True:
                try:
                    conn, addr = srv.accept()
                    ip = addr[0]
                    allowed = detector.record_request(ip)
                    if not allowed:
                        print(f"  {Fore.RED}[BLOCKED] {ip}{Style.RESET_ALL}")
                        conn.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
                    conn.close()
                except: pass
        except KeyboardInterrupt:
            stats = detector.get_stats()
            print(f"\n{Fore.CYAN}Stats: {stats}")

    else:  # simulate (default)
        print(f"{Fore.CYAN}[*] Generando patrones de ataque sintéticos...\n")
        patterns = simulate_attack_patterns()
        result   = analyze_attack(patterns)

        print(f"  Total requests : {result['total_requests']}")
        print(f"  {Fore.GREEN}Permitidos     : {result['allowed']}")
        print(f"  {Fore.RED}Bloqueados     : {result['blocked']} ({result['block_rate']}%){Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}Tipos de ataque:{Style.RESET_ALL}")
        for t,c in result["attack_types"].items():
            print(f"    {t:<15}: {c}")
        print(f"\n  {Fore.RED}Top atacantes:{Style.RESET_ALL}")
        for ip, count in result["top_attackers"]:
            print(f"    {ip:<20}: {count} requests")
        print(f"\n  {Fore.CYAN}Alertas generadas: {len(result['alerts'])}")
        for a in result["alerts"][:5]:
            print(f"    {Fore.RED}[{a['level']}] {a['ip']} — {a['rps']} req/s{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
