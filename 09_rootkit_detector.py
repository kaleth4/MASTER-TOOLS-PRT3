#!/usr/bin/env python3
"""09 · ROOTKIT DETECTOR — Detect rootkit indicators on Linux/Windows"""

import os, sys, subprocess, re, json, argparse, platform
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🕵️  ROOTKIT DETECTOR  v1.0          ║\n║  Detect hidden processes & files     ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

KNOWN_ROOTKITS = [
    "azazel","bdvl","beurk","cub3","Diamorphine","Drovorub","Azazel",
    "LKM","Necurs","r77","Reptile","Reptile","Rkill","Rkunhide",
    "TDSS","TDL","Turla","Umbreon","Vitaly",
]

SUSPICIOUS_KERNEL_MODULES = [
    "hide_module","rootkit","invis","diamorphine","reptile",
    "azazel","umbreon","necurs","lkm",
]

def get_proc_list_ps() -> list:
    """Get process list via ps command."""
    try:
        out = subprocess.check_output(["ps","aux"], text=True, stderr=subprocess.DEVNULL)
        pids = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts and parts[1].isdigit():
                pids.append(int(parts[1]))
        return pids
    except: return []

def get_proc_list_proc() -> list:
    """Get process list via /proc (Linux)."""
    if os.name == "nt": return []
    try:
        return [int(d) for d in os.listdir("/proc") if d.isdigit()]
    except: return []

def detect_hidden_processes() -> list:
    """Compare ps output vs /proc listing — rootkits hide from ps."""
    hidden = []
    if platform.system() != "Linux": return hidden
    proc_pids = set(get_proc_list_proc())
    ps_pids   = set(get_proc_list_ps())
    # PIDs in /proc but not in ps = potentially hidden
    diff = proc_pids - ps_pids
    for pid in diff:
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            hidden.append({"pid":pid,"name":name,
                            "note":"En /proc pero no en ps — posible rootkit"})
        except: pass
    return hidden

def check_kernel_modules() -> list:
    """Check loaded kernel modules for suspicious entries."""
    suspicious = []
    if platform.system() != "Linux": return suspicious
    try:
        out = subprocess.check_output(["lsmod"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            name = line.split()[0].lower() if line.split() else ""
            for sus in SUSPICIOUS_KERNEL_MODULES:
                if sus in name:
                    suspicious.append({"module":name,"reason":f"Nombre sospechoso: {sus}"})
                    break
    except: pass
    # Also check /proc/modules
    try:
        with open("/proc/modules") as f:
            for line in f:
                name = line.split()[0].lower()
                for sus in SUSPICIOUS_KERNEL_MODULES:
                    if sus in name and name not in [s["module"] for s in suspicious]:
                        suspicious.append({"module":name,"reason":"En /proc/modules — sospechoso"})
    except: pass
    return suspicious

def check_ld_preload() -> list:
    """Check for LD_PRELOAD rootkit (userspace hooking)."""
    issues = []
    # Check environment variable
    ldp = os.environ.get("LD_PRELOAD","")
    if ldp:
        issues.append({"type":"LD_PRELOAD","value":ldp,"level":"CRÍTICO",
                        "note":"LD_PRELOAD activo — posible userland rootkit"})
    # Check /etc/ld.so.preload
    ld_file = "/etc/ld.so.preload"
    if os.path.isfile(ld_file):
        try:
            with open(ld_file) as f:
                content = f.read().strip()
            if content:
                issues.append({"type":"ld.so.preload","value":content,"level":"CRÍTICO",
                                "note":f"Libs pre-cargadas: {content[:100]}"})
        except: pass
    return issues

def check_suid_binaries() -> list:
    """Find unexpected SUID binaries (rootkits often create them)."""
    known_suid = {
        "/usr/bin/sudo","/usr/bin/su","/bin/su","/usr/bin/passwd",
        "/usr/bin/chsh","/usr/bin/newgrp","/usr/bin/gpasswd",
        "/bin/ping","/usr/bin/ping","/usr/bin/pkexec",
    }
    suspicious = []
    if platform.system() != "Linux": return suspicious
    try:
        out = subprocess.check_output(
            ["find","/","(","-perm","-4000","-o","-perm","-2000",")",
             "-type","f","2>/dev/null"],
            text=True, stderr=subprocess.DEVNULL, timeout=30
        )
        for line in out.splitlines():
            line = line.strip()
            if line and line not in known_suid:
                suspicious.append({"path":line,"note":"SUID binario no estándar"})
    except: pass
    return suspicious[:20]

def check_network_backdoors() -> list:
    """Look for unusual listening ports that could be backdoors."""
    backdoor_ports = {4444,1337,31337,8888,12345,54321,9999,6666,7777}
    found = []
    try:
        if platform.system() == "Linux":
            out = subprocess.check_output(["ss","-tlnp"], text=True, stderr=subprocess.DEVNULL)
        else:
            out = subprocess.check_output(["netstat","-an"], text=True)
        for port in backdoor_ports:
            if f":{port}" in out or f" {port} " in out:
                found.append({"port":port,"note":"Puerto típico de backdoor/shell"})
    except: pass
    return found

def check_startup_persistence() -> list:
    """Check common persistence locations."""
    locations = []
    if platform.system() == "Linux":
        paths = [
            "/etc/crontab", "/etc/rc.local", "/etc/init.d",
            "/etc/systemd/system", "/var/spool/cron",
            os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.bash_profile"),
        ]
        for path in paths:
            if os.path.exists(path):
                try:
                    if os.path.isfile(path):
                        with open(path) as f:
                            content = f.read()
                        suspicious_cmds = ["wget","curl","bash","nc ","ncat","python","perl"]
                        for cmd in suspicious_cmds:
                            if cmd in content:
                                locations.append({"path":path,"command":cmd,
                                                   "level":"ALTO"})
                                break
                except: pass
    return locations

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Rootkit Detector")
    parser.add_argument("--all",     action="store_true", default=True)
    parser.add_argument("--procs",   action="store_true")
    parser.add_argument("--modules", action="store_true")
    parser.add_argument("--preload", action="store_true")
    parser.add_argument("--suid",    action="store_true")
    parser.add_argument("--ports",   action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("-o","--output", default=None)
    args = parser.parse_args()

    all_findings = {}
    checks = [
        ("Procesos ocultos",     detect_hidden_processes,    "procs"),
        ("Módulos kernel",       check_kernel_modules,       "modules"),
        ("LD_PRELOAD",           check_ld_preload,            "preload"),
        ("SUID sospechosos",     check_suid_binaries,        "suid"),
        ("Puertos backdoor",     check_network_backdoors,    "ports"),
        ("Persistencia",         check_startup_persistence,  "persist"),
    ]

    for name, fn, flag in checks:
        print(f"\n{Fore.CYAN}[*] Verificando: {name}...{Style.RESET_ALL}")
        try:
            results = fn()
            all_findings[name] = results
            if results:
                for r in results[:5]:
                    level = r.get("level","ALTO")
                    c = Fore.RED if level in ("CRÍTICO","ALTO") else Fore.YELLOW
                    key = next(iter(r))
                    print(f"  {c}[{level}]{Style.RESET_ALL} {r.get('note',r.get('reason',''))}: "
                          f"{Fore.YELLOW}{r.get(key,'')}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}✓ Sin indicadores{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.GRAY}Error: {e}{Style.RESET_ALL}")

    total = sum(len(v) for v in all_findings.values())
    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.RED if total>0 else Fore.GREEN}Total indicadores: {total}")

    if args.output:
        with open(args.output,"w") as f:
            json.dump(all_findings, f, indent=2, default=str)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
