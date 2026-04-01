#!/usr/bin/env python3
"""14 · CONTAINER SECURITY SCANNER — Docker/K8s security assessment"""
import subprocess,json,argparse,os,re
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🐳 CONTAINER SECURITY  v1.0         ║\n║  Docker · Kubernetes · Microservices ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"
DANGEROUS_CAPS=["SYS_ADMIN","SYS_PTRACE","NET_ADMIN","ALL"]
def run(cmd):
    try:
        return subprocess.check_output(cmd,text=True,stderr=subprocess.DEVNULL)
    except:return ""
def check_docker_config()->list:
    findings=[]
    # Check Docker daemon config
    daemon_cfg="/etc/docker/daemon.json"
    if os.path.isfile(daemon_cfg):
        try:
            with open(daemon_cfg) as f:cfg=json.load(f)
            if not cfg.get("userns-remap"):
                findings.append({"level":"ALTO","msg":"User namespace remapping no configurado"})
            if cfg.get("icc",True):
                findings.append({"level":"MEDIO","msg":"Inter-container communication habilitado (icc=true)"})
            if not cfg.get("no-new-privileges"):
                findings.append({"level":"MEDIO","msg":"no-new-privileges no configurado"})
        except:pass
    # Check running containers
    containers_out=run(["docker","ps","--format","{{json .}}"])
    if not containers_out:return findings
    for line in containers_out.strip().splitlines():
        try:
            c=json.loads(line)
            cid=c.get("ID","?")[:12]
            name=c.get("Names","?")
            # Inspect container
            inspect_out=run(["docker","inspect",cid])
            if not inspect_out:continue
            inspect=json.loads(inspect_out)[0]
            # Privileged
            if inspect.get("HostConfig",{}).get("Privileged"):
                findings.append({"level":"CRÍTICO","msg":f"Container '{name}' running PRIVILEGED","container":cid})
            # Capabilities
            caps=inspect.get("HostConfig",{}).get("CapAdd",[]) or []
            for cap in caps:
                if cap in DANGEROUS_CAPS:
                    findings.append({"level":"CRÍTICO","msg":f"Dangerous capability: {cap} in '{name}'","container":cid})
            # Root user
            user=inspect.get("Config",{}).get("User","")
            if not user or user in ("0","root"):
                findings.append({"level":"ALTO","msg":f"Container '{name}' running as root","container":cid})
            # Exposed ports
            ports=inspect.get("NetworkSettings",{}).get("Ports",{})
            for port_proto,bindings in ports.items():
                if bindings:
                    for b in bindings:
                        if b.get("HostIp","")=="0.0.0.0":
                            findings.append({"level":"MEDIO","msg":f"Port {port_proto} bound to 0.0.0.0 in '{name}'","container":cid})
            # Sensitive mounts
            mounts=inspect.get("HostConfig",{}).get("Binds",[]) or []
            for mount in mounts:
                if any(s in mount for s in ["/var/run/docker.sock","/etc","/proc","/sys"]):
                    findings.append({"level":"CRÍTICO","msg":f"Sensitive mount: {mount} in '{name}'","container":cid})
        except:pass
    return findings
def check_k8s()->list:
    findings=[]
    kubectl_out=run(["kubectl","get","pods","--all-namespaces","-o","json"])
    if not kubectl_out:return findings
    try:
        data=json.loads(kubectl_out)
        for item in data.get("items",[]):
            name=item.get("metadata",{}).get("name","?")
            ns=item.get("metadata",{}).get("namespace","default")
            spec=item.get("spec",{})
            containers=spec.get("containers",[])
            for c in containers:
                sc=c.get("securityContext",{})
                if sc.get("privileged"):
                    findings.append({"level":"CRÍTICO","msg":f"Privileged pod: {name} in ns:{ns}"})
                if not sc.get("runAsNonRoot"):
                    findings.append({"level":"ALTO","msg":f"Pod may run as root: {name}"})
                if not sc.get("readOnlyRootFilesystem"):
                    findings.append({"level":"MEDIO","msg":f"Writable root filesystem: {name}"})
                if sc.get("allowPrivilegeEscalation",True):
                    findings.append({"level":"MEDIO","msg":f"Privilege escalation allowed: {name}"})
                for cap in (sc.get("capabilities",{}).get("add",[]) or []):
                    if cap in DANGEROUS_CAPS:
                        findings.append({"level":"CRÍTICO","msg":f"Dangerous cap {cap} in pod {name}"})
    except:pass
    return findings
def analyze_dockerfile(path:str)->list:
    findings=[]
    if not os.path.isfile(path):return findings
    with open(path) as f:lines=f.readlines()
    has_user=False
    for i,line in enumerate(lines,1):
        line=line.strip()
        if line.upper().startswith("USER"):
            user=line.split()[-1].lower()
            if user in("root","0"):
                findings.append({"level":"CRÍTICO","line":i,"msg":"Running as root user"})
            else:has_user=True
        if line.upper().startswith("ADD") and ("http://" in line or "https://" in line):
            findings.append({"level":"MEDIO","line":i,"msg":"ADD with URL — use COPY + RUN curl instead"})
        if line.upper().startswith("RUN") and "apt-get" in line.lower() and "--no-install-recommends" not in line:
            findings.append({"level":"BAJO","line":i,"msg":"apt-get without --no-install-recommends (bloated image)"})
        if re.search(r"(password|secret|key|token)\s*=\s*\S+",line,re.I):
            findings.append({"level":"CRÍTICO","line":i,"msg":f"Hardcoded secret in Dockerfile: {line[:60]}"})
        if "EXPOSE 22" in line.upper():
            findings.append({"level":"ALTO","line":i,"msg":"SSH exposed in container"})
        if "privileged" in line.lower():
            findings.append({"level":"CRÍTICO","line":i,"msg":"Privileged flag in Dockerfile"})
    if not has_user:
        findings.append({"level":"ALTO","line":0,"msg":"No USER instruction — container may run as root"})
    return findings
def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="Container Security Scanner")
    sub=parser.add_subparsers(dest="cmd")
    sub.add_parser("docker",help="Scan running Docker containers")
    sub.add_parser("k8s",   help="Scan Kubernetes pods")
    df_p=sub.add_parser("dockerfile",help="Analyze Dockerfile")
    df_p.add_argument("path",default="Dockerfile",nargs="?")
    parser.add_argument("-o","--output",default=None)
    args=parser.parse_args()
    findings=[]
    if args.cmd=="docker":
        print(f"\n{Fore.CYAN}[*] Escaneando contenedores Docker...\n")
        findings=check_docker_config()
    elif args.cmd=="k8s":
        print(f"\n{Fore.CYAN}[*] Escaneando pods Kubernetes...\n")
        findings=check_k8s()
    elif args.cmd=="dockerfile":
        print(f"\n{Fore.CYAN}[*] Analizando: {args.path}\n")
        findings=analyze_dockerfile(args.path)
    else:
        print(f"\n  Comandos: docker, k8s, dockerfile [path]")
        print(f"  Ejemplo: python3 14_container_security.py dockerfile ./Dockerfile")
        return
    if not findings:
        print(f"{Fore.GREEN}[✓] Sin hallazgos críticos")
    else:
        for f in findings:
            level=f.get("level","INFO")
            c=Fore.RED if level in("CRÍTICO","ALTO") else Fore.YELLOW
            line=f"  Line {f['line']}:" if f.get("line") else ""
            print(f"  {c}[{level}]{Style.RESET_ALL}{line} {f['msg']}")
    print(f"\n{Fore.CYAN}Total: {len(findings)}")
    if args.output:
        with open(args.output,"w") as f2:json.dump(findings,f2,indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")
if __name__=="__main__":main()
