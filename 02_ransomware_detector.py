#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  02 · RANSOMWARE DETECTOR            ║
║  Monitor filesystem for encryption   ║
╚══════════════════════════════════════╝
Detecta actividad de ransomware:
- Cambios masivos de extensión
- Alta entropía en archivos
- Creación de notas de rescate
Usage: python3 02_ransomware_detector.py -d /path/to/monitor
"""

import os, sys, time, math, json, argparse, threading, hashlib
from datetime import datetime
from collections import Counter
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════╗
║  🔐 RANSOMWARE DETECTOR  v1.0        ║
║  Real-time filesystem monitoring     ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

# Extensiones conocidas de ransomware
RANSOM_EXTENSIONS = {
    ".locked",".encrypted",".crypto",".enc",".cerber",".zepto",
    ".locky",".crypt",".ctbl",".ctb2",".onion",".zzzzz",".micro",
    ".evil",".good",".ttt",".vvv",".xxx",".aaa",".abc",".xyz",
    ".wallet",".globe",".odin",".thor",".xtbl",".WNCRY",".wcry",
    ".kraken",".darkness",".nochance",".pay2me",".bad",".fun",
}

RANSOM_NOTE_NAMES = {
    "readme.txt","read_me.txt","how_to_decrypt.txt","decrypt_files.txt",
    "ransom.txt","recovery.txt","your_files_are_encrypted.txt",
    "help_decrypt.html","how_decrypt.html","!!!_readme_!!!.txt",
    "decrypt_instructions.txt","_readme_.txt","read_this.txt",
}

alerts       = []
file_baseline= {}
lock         = threading.Lock()

def file_entropy(path: str) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(65536)  # first 64KB
        if not data: return 0.0
        freq  = Counter(data)
        total = len(data)
        return -sum((c/total)*math.log2(c/total) for c in freq.values())
    except: return 0.0

def file_hash(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except: return ""

def build_baseline(directory: str) -> dict:
    baseline = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                stat = os.stat(path)
                baseline[path] = {
                    "size":  stat.st_size,
                    "mtime": stat.st_mtime,
                    "hash":  file_hash(path),
                    "ext":   os.path.splitext(fname)[1].lower(),
                }
            except: pass
    return baseline

def check_ransom_extension(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in RANSOM_EXTENSIONS

def check_ransom_note(path: str) -> bool:
    return os.path.basename(path).lower() in RANSOM_NOTE_NAMES

def alert(level: str, msg: str, path: str = ""):
    ts    = datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "level": level, "msg": msg, "path": path}
    with lock:
        alerts.append(entry)
    color = Fore.RED if level == "CRÍTICO" else Fore.YELLOW
    print(f"\n  {Fore.RED}╔══ ALERTA ══════════════════════════╗{Style.RESET_ALL}")
    print(f"  {color}[{level}] {msg}{Style.RESET_ALL}")
    if path:
        print(f"  {Fore.GRAY}Archivo: {path}{Style.RESET_ALL}")
    print(f"  {Fore.RED}╚════════════════════════════════════╝{Style.RESET_ALL}")

def scan_directory(directory: str) -> dict:
    """Análisis estático de un directorio."""
    results = {
        "directory":     directory,
        "total_files":   0,
        "ransom_ext":    [],
        "ransom_notes":  [],
        "high_entropy":  [],
        "encrypted_pct": 0,
    }

    ext_counter = Counter()
    for root, _, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            results["total_files"] += 1
            ext  = os.path.splitext(fname)[1].lower()
            ext_counter[ext] += 1

            if check_ransom_extension(path):
                results["ransom_ext"].append(path)

            if check_ransom_note(path):
                results["ransom_notes"].append(path)

            # Check entropy for non-text files
            if ext not in (".txt",".py",".js",".html",".css",".xml",".json"):
                ent = file_entropy(path)
                if ent > 7.5:
                    results["high_entropy"].append({"path":path,"entropy":round(ent,3)})

    if results["total_files"] > 0:
        results["encrypted_pct"] = round(
            len(results["ransom_ext"]) / results["total_files"] * 100, 1
        )
    return results

def monitor(directory: str, interval: float = 2.0):
    """Monitoreo en tiempo real."""
    print(f"{Fore.CYAN}[*] Construyendo baseline de {directory}...")
    baseline = build_baseline(directory)
    print(f"{Fore.GREEN}[✓] Baseline: {len(baseline)} archivos")
    print(f"{Fore.CYAN}[*] Monitoreando (Ctrl+C para detener)...\n")

    ext_changes  = Counter()
    files_changed= 0

    try:
        while True:
            time.sleep(interval)
            current_files = set()

            for root, _, files in os.walk(directory):
                for fname in files:
                    path = os.path.join(root, fname)
                    current_files.add(path)
                    ext  = os.path.splitext(fname)[1].lower()

                    # New file
                    if path not in baseline:
                        if check_ransom_note(path):
                            alert("CRÍTICO", f"Nota de rescate creada: {fname}", path)
                        if check_ransom_extension(path):
                            alert("CRÍTICO", f"Extensión ransomware: {ext}", path)
                            ext_changes[ext] += 1
                        baseline[path] = {"ext": ext, "mtime": 0, "hash":"", "size":0}
                        files_changed += 1
                    else:
                        # Modified file
                        try:
                            mtime = os.stat(path).st_mtime
                            if mtime != baseline[path].get("mtime",0):
                                new_hash = file_hash(path)
                                if new_hash != baseline[path].get("hash",""):
                                    ent = file_entropy(path)
                                    if ent > 7.5:
                                        alert("ALTO",
                                              f"Archivo modificado con alta entropía ({ent:.2f})",
                                              path)
                                    files_changed += 1
                                baseline[path]["mtime"] = mtime
                        except: pass

            # Mass change detection
            deleted = set(baseline.keys()) - current_files
            if len(deleted) > 10:
                alert("CRÍTICO",
                      f"{len(deleted)} archivos eliminados en {interval}s — posible cifrado masivo")

            if files_changed > 50:
                alert("CRÍTICO",
                      f"{files_changed} archivos cambiados — comportamiento ransomware detectado")
                files_changed = 0

            sys.stdout.write(f"\r  {Fore.GRAY}[Monitoreando] "
                             f"Files: {len(current_files)}  "
                             f"Alertas: {len(alerts)}{Style.RESET_ALL}   ")
            sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Monitoreo detenido. Alertas: {len(alerts)}")

def print_scan_result(r: dict):
    total = r["total_files"]
    print(f"\n  {Fore.CYAN}Directorio: {r['directory']}")
    print(f"  Total archivos: {total}")
    print(f"  % con ext ransomware: {r['encrypted_pct']}%\n")

    if r["ransom_notes"]:
        print(f"  {Fore.RED}[CRÍTICO] Notas de rescate encontradas:{Style.RESET_ALL}")
        for n in r["ransom_notes"]:
            print(f"    {Fore.RED}⚠ {n}{Style.RESET_ALL}")

    if r["ransom_ext"]:
        print(f"  {Fore.RED}[CRÍTICO] Extensiones ransomware:{Style.RESET_ALL}")
        for e in r["ransom_ext"][:10]:
            print(f"    {Fore.RED}⚠ {e}{Style.RESET_ALL}")

    if r["high_entropy"]:
        print(f"  {Fore.YELLOW}[ALTO] Alta entropía (posible cifrado):{Style.RESET_ALL}")
        for e in r["high_entropy"][:5]:
            print(f"    {Fore.YELLOW}⚠ {e['path']} — {e['entropy']} bits{Style.RESET_ALL}")

    if not r["ransom_notes"] and not r["ransom_ext"] and not r["high_entropy"]:
        print(f"  {Fore.GREEN}[✓] Sin indicadores de ransomware detectados{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ransomware Detector")
    parser.add_argument("-d","--dir",     default=".", help="Directorio a monitorear/escanear")
    parser.add_argument("--scan",         action="store_true", help="Escaneo estático único")
    parser.add_argument("--monitor",      action="store_true", help="Monitoreo en tiempo real")
    parser.add_argument("-i","--interval",type=float, default=2.0)
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"{Fore.RED}[✗] Directorio no encontrado: {args.dir}"); sys.exit(1)

    if args.monitor:
        monitor(args.dir, args.interval)
    else:
        print(f"{Fore.CYAN}[*] Escaneando: {args.dir}\n")
        r = scan_directory(args.dir)
        print_scan_result(r)

        if r["ransom_ext"] or r["ransom_notes"]:
            print(f"\n{Fore.RED}[!] POSIBLE INFECCIÓN DE RANSOMWARE DETECTADA")
            print(f"    Acción inmediata: desconectar de la red, no apagar el equipo,")
            print(f"    contactar al equipo de IR (Incident Response).{Style.RESET_ALL}")

        if args.output:
            with open(args.output,"w") as f:
                json.dump(r, f, indent=2)
            print(f"\n{Fore.CYAN}[*] Reporte: {args.output}")

if __name__ == "__main__":
    main()
