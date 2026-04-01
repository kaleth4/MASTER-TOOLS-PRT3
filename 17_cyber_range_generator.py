#!/usr/bin/env python3
"""17 · CYBER RANGE SCENARIO GENERATOR — CTF and lab scenario creator"""
import json,argparse,random,secrets,os
from datetime import datetime
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🎯 CYBER RANGE GENERATOR  v1.0      ║\n║  CTF scenarios · Lab challenges      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"
SCENARIO_TEMPLATES={
    "web_exploitation":{
        "name":"Web Application Attack Chain",
        "difficulty":"Intermediate",
        "category":"Web Security",
        "time_estimate":"2-3 hours",
        "objectives":["Enumerate web application endpoints","Find and exploit SQL injection","Bypass authentication","Escalate to admin panel","Extract sensitive data from database"],
        "flags":["CTF{sql_1nj3ct10n_f0und}","CTF{4uth_byp4ss_succ3ss}","CTF{d4t4_3xf1ltr4t10n}"],
        "hints":["Check for error messages when manipulating parameters","Try UNION-based SQL injection in search field","Look for cookies without HttpOnly flag"],
        "tools":["sqlmap","Burp Suite","curl","browser dev tools"],
        "setup":{"required":["DVWA or custom Flask app","MySQL database","Docker container"],"network":"isolated_lab_net"},
    },
    "network_intrusion":{
        "name":"Network Penetration Test",
        "difficulty":"Advanced",
        "category":"Network Security",
        "time_estimate":"4-5 hours",
        "objectives":["Discover all hosts in 192.168.1.0/24","Identify open services","Exploit vulnerable service","Gain foothold","Pivot to internal network","Find the flag file"],
        "flags":["CTF{n3tw0rk_r3c0n_m4st3r}","CTF{s3rv1c3_3xpl01t3d}","CTF{p1v0t_succ3ssful}"],
        "hints":["Start with nmap -sV for service versions","Check for known CVEs of found services","netcat can be useful for pivoting"],
        "tools":["nmap","metasploit","netcat","proxychains"],
        "setup":{"required":["Metasploitable VM","Kali Linux attacker","Isolated network"],"network":"lab_192.168.1.0/24"},
    },
    "forensics":{
        "name":"Digital Forensics Investigation",
        "difficulty":"Intermediate",
        "category":"Digital Forensics",
        "time_estimate":"3-4 hours",
        "objectives":["Analyze disk image","Find deleted files","Recover email artifacts","Identify malware","Extract hidden data from images"],
        "flags":["CTF{d3l3t3d_f1l3_r3c0v3r3d}","CTF{m4lw4r3_1d3nt1f13d}","CTF{st3g4n0_s3cr3t}"],
        "hints":["Use Autopsy or FTK for disk analysis","Check file metadata with exiftool","Look for steganography in images"],
        "tools":["Autopsy","Volatility","strings","binwalk","steghide"],
        "setup":{"required":["Prepared disk image","Memory dump","Suspicious images"],"network":"offline"},
    },
    "cryptography":{
        "name":"Cryptography Challenge",
        "difficulty":"Beginner-Intermediate",
        "category":"Cryptography",
        "time_estimate":"2-3 hours",
        "objectives":["Decode Base64 encoded message","Break Caesar cipher","Crack MD5 hash with wordlist","Decrypt AES with found key","RSA with small exponent"],
        "flags":["CTF{b4s364_d3c0d3d}","CTF{c43s4r_c1ph3r}","CTF{h4sh_cr4ck3d}"],
        "hints":["Try cyberchef for encoding detection","Frequency analysis for classical ciphers","Rockyou.txt for hash cracking"],
        "tools":["CyberChef","hashcat","openssl","Python"],
        "setup":{"required":["Challenge files","Wordlist (rockyou.txt)"],"network":"offline"},
    },
    "reverse_engineering":{
        "name":"Reverse Engineering Binary",
        "difficulty":"Advanced",
        "category":"Reverse Engineering",
        "time_estimate":"4-6 hours",
        "objectives":["Static analysis of binary","Find hardcoded strings","Bypass license check","Patch binary to unlock feature","Extract hidden flag"],
        "flags":["CTF{r3v3rs3d_ch3ck}","CTF{p4tch3d_b1n4ry}","CTF{h1dd3n_fl4g_found}"],
        "hints":["strings command to find readable text","IDA Free or Ghidra for decompilation","GDB for dynamic analysis"],
        "tools":["Ghidra","IDA Free","GDB","radare2","strings","ltrace","strace"],
        "setup":{"required":["Challenge binary (ELF/PE)","Linux VM or Windows VM"],"network":"offline"},
    },
}
def generate_ctf_flag(prefix:str="CTF",challenge:str="")->str:
    if challenge:
        tag=challenge[:8].lower().replace(" ","_")
        return f"{prefix}{{{tag}_{secrets.token_hex(6)}}}"
    return f"{prefix}{{{secrets.token_hex(12)}}}"
def generate_scenario(template_name:str,team_name:str="Team",difficulty:str=None)->dict:
    template=SCENARIO_TEMPLATES.get(template_name,list(SCENARIO_TEMPLATES.values())[0])
    scenario={
        "id":secrets.token_hex(4).upper(),
        "generated":datetime.now().isoformat(),
        "team":team_name,
        "scenario_name":template["name"],
        "category":template["category"],
        "difficulty":difficulty or template["difficulty"],
        "time_limit_minutes":int(template["time_estimate"].split("-")[0].strip())*60,
        "objectives":template["objectives"],
        "flags":[generate_ctf_flag(challenge=obj[:15]) for obj in template["objectives"]],
        "hints":template["hints"],
        "required_tools":template["tools"],
        "setup":template["setup"],
        "scoring":{
            "max_points":len(template["objectives"])*100,
            "points_per_flag":100,
            "hint_penalty":-25,
            "time_bonus":"10 pts per 10 min under limit",
        },
    }
    return scenario
def generate_network_diagram(hosts:int=5)->dict:
    """Generate a fictional but realistic lab network."""
    diagram={"network":"192.168.1.0/24","hosts":[]}
    services_pool=[
        ("22","SSH","OpenSSH 7.4"),("80","HTTP","Apache 2.4.49"),
        ("443","HTTPS","nginx 1.14"),("21","FTP","vsftpd 2.3.4"),
        ("3306","MySQL","MySQL 5.7"),("445","SMB","Samba 4.x"),
        ("6379","Redis","Redis 6.0"),("8080","HTTP-Alt","Tomcat 9.0"),
    ]
    for i in range(1,hosts+1):
        host_type=random.choice(["Web Server","DB Server","File Server","Mail Server","Workstation"])
        num_services=random.randint(2,4)
        services=random.sample(services_pool,num_services)
        diagram["hosts"].append({
            "ip":f"192.168.1.{i+10}",
            "type":host_type,
            "os":random.choice(["Ubuntu 20.04","CentOS 7","Windows Server 2019","Debian 11"]),
            "services":[{"port":p,"name":n,"version":v} for p,n,v in services],
            "flag_location":random.choice(["/root/flag.txt","C:\\flag.txt","/home/user/secret.txt","/var/www/html/flag.php"]),
        })
    return diagram
def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="Cyber Range Scenario Generator")
    sub=parser.add_subparsers(dest="cmd")
    sc_p=sub.add_parser("scenario",help="Generar escenario CTF")
    sc_p.add_argument("-t","--type",choices=list(SCENARIO_TEMPLATES.keys()),default="web_exploitation")
    sc_p.add_argument("--team",default="Team")
    sc_p.add_argument("-d","--difficulty",default=None,choices=["Beginner","Intermediate","Advanced"])
    sc_p.add_argument("-o","--output",default=None)
    net_p=sub.add_parser("network",help="Generar diagrama de red de laboratorio")
    net_p.add_argument("-n","--hosts",type=int,default=5)
    net_p.add_argument("-o","--output",default=None)
    ls_p=sub.add_parser("list",help="Listar templates disponibles")
    args=parser.parse_args()
    if args.cmd=="list":
        print(f"\n{Fore.CYAN}Templates disponibles:{Style.RESET_ALL}")
        for name,t in SCENARIO_TEMPLATES.items():
            print(f"  {Fore.YELLOW}{name:<25}{Style.RESET_ALL} {t['difficulty']:<15} {t['category']}")
    elif args.cmd=="network":
        diagram=generate_network_diagram(args.hosts)
        print(f"\n{Fore.CYAN}[*] Lab Network: {diagram['network']}\n")
        for h in diagram["hosts"]:
            print(f"  {Fore.GREEN}{h['ip']:<18}{Style.RESET_ALL} {h['type']:<18} {h['os']}")
            for s in h["services"]:
                print(f"    Port {s['port']:<6} {s['name']:<12} {s['version']}")
        if args.output:
            with open(args.output,"w") as f:json.dump(diagram,f,indent=2)
            print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")
    else:
        sc=generate_scenario(getattr(args,"type","web_exploitation"),
                              getattr(args,"team","Team"),
                              getattr(args,"difficulty",None))
        print(f"\n  {Fore.CYAN}Escenario: {sc['scenario_name']}")
        print(f"  ID       : {sc['id']}")
        print(f"  Equipo   : {sc['team']}")
        print(f"  Dificultad: {sc['difficulty']}")
        print(f"  Tiempo   : {sc['time_limit_minutes']//60}h")
        print(f"\n  {Fore.CYAN}Objetivos ({len(sc['objectives'])}):{Style.RESET_ALL}")
        for i,(obj,flag) in enumerate(zip(sc["objectives"],sc["flags"]),1):
            print(f"  {i}. {obj}")
            print(f"     {Fore.YELLOW}Flag: {flag}{Style.RESET_ALL}")
        print(f"\n  {Fore.CYAN}Herramientas: {', '.join(sc['required_tools'])}")
        print(f"  Puntos max: {sc['scoring']['max_points']}")
        out=getattr(args,"output",None)
        if out:
            with open(out,"w") as f:json.dump(sc,f,indent=2)
            print(f"\n{Fore.CYAN}[*] Guardado: {out}")
if __name__=="__main__":main()
