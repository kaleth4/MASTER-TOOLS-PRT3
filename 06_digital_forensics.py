#!/usr/bin/env python3
"""06 · DIGITAL FORENSICS ANALYZER — File timeline, deleted files, artifacts"""

import os, sys, argparse, json, hashlib, stat, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🔬 DIGITAL FORENSICS  v1.0          ║\n║  Timeline · Artifacts · Evidence     ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

SUSPICIOUS_ARTIFACTS = {
    "linux": [
        "/tmp","/.bash_history","/var/log/auth.log","/root/.ssh",
        "/etc/crontab","/var/spool/cron","/tmp/.ICE-unix",
        "/dev/shm","/proc/*/maps",
    ],
    "windows": [
        r"C:\Users\*\AppData\Roaming",r"C:\Windows\Temp",
        r"C:\Windows\System32\Tasks",r"C:\ProgramData",
    ],
}

MALWARE_INDICATORS = [
    (r"\.exe$",  "Executable"),
    (r"\.dll$",  "Dynamic Library"),
    (r"\.bat$",  "Batch Script"),
    (r"\.ps1$",  "PowerShell Script"),
    (r"\.vbs$",  "VBScript"),
    (r"\.js$",   "JavaScript"),
    (r"base64",  "Base64 in filename"),
    (r"temp|tmp","Temp file"),
    (r"\.bak$",  "Backup file"),
]

def file_hash(path: str, algo: str = "md5") -> str:
    try:
        h = hashlib.new(algo)
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except: return ""

def get_file_timestamps(path: str) -> dict:
    try:
        s = os.stat(path)
        return {
            "accessed": datetime.fromtimestamp(s.st_atime).isoformat(),
            "modified": datetime.fromtimestamp(s.st_mtime).isoformat(),
            "created":  datetime.fromtimestamp(s.st_ctime).isoformat(),
            "size":     s.st_size,
            "perms":    oct(stat.S_IMODE(s.st_mode)),
            "uid":      s.st_uid,
            "gid":      s.st_gid,
        }
    except Exception as e:
        return {"error": str(e)}

def extract_strings(path: str, min_len: int = 6) -> list:
    try:
        with open(path,"rb") as f:
            data = f.read(1024*1024)  # 1MB max
        pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
        strings  = re.findall(pattern, data)
        return [s.decode("ascii","replace") for s in strings[:100]]
    except: return []

def build_timeline(directory: str) -> list:
    events = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in (".git","node_modules","__pycache__")]
        for fname in files:
            path = os.path.join(root, fname)
            ts   = get_file_timestamps(path)
            if "error" not in ts:
                events.append({"path":path,"file":fname,**ts})
    events.sort(key=lambda x: x.get("modified",""))
    return events

def find_suspicious_files(directory: str) -> list:
    suspicious = []
    for root, _, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            for pattern, desc in MALWARE_INDICATORS:
                if re.search(pattern, fname, re.IGNORECASE):
                    ts = get_file_timestamps(path)
                    suspicious.append({"path":path,"reason":desc,"timestamps":ts})
                    break
    return suspicious

def find_hidden_files(directory: str) -> list:
    hidden = []
    for root, dirs, files in os.walk(directory):
        for name in files + dirs:
            if name.startswith(".") and name not in (".","..",".gitignore",".env"):
                path = os.path.join(root, name)
                hidden.append({"path":path,"type":"dir" if os.path.isdir(path) else "file"})
    return hidden

def check_suid_sgid(directory: str = "/") -> list:
    results = []
    if os.name == "nt": return results
    try:
        for root, _, files in os.walk(directory):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    s = os.stat(path)
                    if s.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        results.append({
                            "path":path,
                            "suid": bool(s.st_mode & stat.S_ISUID),
                            "sgid": bool(s.st_mode & stat.S_ISGID),
                        })
                except: pass
    except PermissionError: pass
    return results[:50]

def generate_evidence_report(directory: str) -> dict:
    print(f"{Fore.CYAN}[*] Construyendo timeline...")
    timeline    = build_timeline(directory)
    print(f"{Fore.CYAN}[*] Buscando archivos sospechosos...")
    suspicious  = find_suspicious_files(directory)
    print(f"{Fore.CYAN}[*] Buscando archivos ocultos...")
    hidden      = find_hidden_files(directory)

    return {
        "directory":    directory,
        "timestamp":    datetime.now().isoformat(),
        "total_files":  len(timeline),
        "timeline":     timeline[-50:],  # últimos 50 modificados
        "suspicious":   suspicious,
        "hidden":       hidden,
    }

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Digital Forensics Analyzer")
    sub = parser.add_subparsers(dest="cmd")

    tl_p = sub.add_parser("timeline", help="Timeline de modificaciones")
    tl_p.add_argument("-d","--dir", required=True)

    sus_p = sub.add_parser("suspicious", help="Archivos sospechosos")
    sus_p.add_argument("-d","--dir", required=True)

    hid_p = sub.add_parser("hidden", help="Archivos ocultos")
    hid_p.add_argument("-d","--dir", required=True)

    fi_p = sub.add_parser("file", help="Analizar archivo específico")
    fi_p.add_argument("path")
    fi_p.add_argument("--strings", action="store_true")

    rep_p = sub.add_parser("report", help="Reporte forense completo")
    rep_p.add_argument("-d","--dir", required=True)
    rep_p.add_argument("-o","--output", default="forensics_report.json")

    args = parser.parse_args()

    if args.cmd == "timeline":
        events = build_timeline(args.dir)
        print(f"\n{Fore.CYAN}[*] Últimos 20 archivos modificados:\n")
        for e in events[-20:]:
            print(f"  {Fore.GRAY}{e['modified'][:19]}{Style.RESET_ALL}  {e['path']}")

    elif args.cmd == "suspicious":
        found = find_suspicious_files(args.dir)
        print(f"\n{Fore.CYAN}[*] Archivos sospechosos: {len(found)}\n")
        for f in found:
            print(f"  {Fore.YELLOW}[{f['reason']}]{Style.RESET_ALL} {f['path']}")

    elif args.cmd == "hidden":
        found = find_hidden_files(args.dir)
        print(f"\n{Fore.CYAN}[*] Archivos/dirs ocultos: {len(found)}\n")
        for f in found:
            print(f"  {Fore.YELLOW}[{f['type']}]{Style.RESET_ALL} {f['path']}")

    elif args.cmd == "file":
        ts = get_file_timestamps(args.path)
        md5 = file_hash(args.path, "md5")
        sha = file_hash(args.path, "sha256")
        print(f"\n  {Fore.CYAN}Archivo: {args.path}")
        for k,v in ts.items(): print(f"  {k:<12}: {v}")
        print(f"  MD5     : {md5}")
        print(f"  SHA256  : {sha}")
        if args.strings:
            strs = extract_strings(args.path)
            print(f"\n  {Fore.CYAN}Strings ({len(strs)}):{Style.RESET_ALL}")
            for s in strs[:20]:
                print(f"  {Fore.GRAY}{s}{Style.RESET_ALL}")

    elif args.cmd == "report":
        r = generate_evidence_report(args.dir)
        print(f"\n{Fore.GREEN}[✓] Reporte generado:")
        print(f"    Archivos    : {r['total_files']}")
        print(f"    Sospechosos : {len(r['suspicious'])}")
        print(f"    Ocultos     : {len(r['hidden'])}")
        with open(args.output,"w") as f:
            json.dump(r, f, indent=2, default=str)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

    else:
        print("  Comandos: timeline, suspicious, hidden, file, report")
        print("  Ejemplo: python3 06_forensics.py report -d /var/www -o evidence.json")

if __name__ == "__main__":
    main()
