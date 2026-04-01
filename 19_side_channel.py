#!/usr/bin/env python3
"""19 · SIDE CHANNEL ATTACK SIMULATOR — Timing & power analysis demo"""
import time,secrets,hmac,hashlib,statistics,argparse,json
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.YELLOW}╔══════════════════════════════════════╗\n║  ⏱️  SIDE CHANNEL SIMULATOR  v1.0    ║\n║  Timing attack · Cache analysis      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def vulnerable_compare(a:str,b:str)->bool:
    """Vulnerable string comparison — exits early on first mismatch."""
    if len(a)!=len(b):return False
    for ca,cb in zip(a,b):
        if ca!=cb:return False
    return True

def constant_time_compare(a:str,b:str)->bool:
    """Constant time comparison — no timing leak."""
    return hmac.compare_digest(a.encode(),b.encode())

def measure_timing(func,a:str,b:str,iterations:int=1000)->float:
    times=[]
    for _ in range(iterations):
        start=time.perf_counter_ns()
        func(a,b)
        times.append(time.perf_counter_ns()-start)
    return statistics.median(times)

def timing_attack_demo(target_password:str="s3cr3t",charset:str="abcdefghijklmnopqrstuvwxyz0123456789!@#")->dict:
    """Demonstrate timing attack to guess password character by character."""
    print(f"\n{Fore.CYAN}[*] Ejecutando timing attack demo...")
    print(f"  Target length: {len(target_password)} chars")
    print(f"  Charset: {len(charset)} chars\n")
    
    guessed=""
    timing_data=[]
    
    for pos in range(min(len(target_password),4)):  # Limit to 4 chars for demo speed
        best_char=""
        best_time=0
        char_times={}
        
        for char in charset[:20]:  # Limit charset for demo
            test=guessed+char+"a"*(len(target_password)-pos-1)
            t=measure_timing(vulnerable_compare,test,target_password,100)
            char_times[char]=t
            if t>best_time:
                best_time=t
                best_char=char
        
        correct=(best_char==target_password[pos])
        guessed+=best_char
        timing_data.append({"pos":pos,"guessed":best_char,"correct":correct,
                              "time_ns":round(best_time),"char_times":{}})
        
        status=f"{Fore.GREEN}✓" if correct else f"{Fore.RED}✗"
        print(f"  Pos {pos}: {status}{Style.RESET_ALL} Guessed='{best_char}' Correct='{target_password[pos]}'  Time={round(best_time)}ns")
    
    return{"target":target_password[:4]+"***","guessed":guessed,"positions":timing_data}

def demonstrate_constant_time()->None:
    print(f"\n{Fore.CYAN}[*] Comparando tiempos vulnerable vs constant-time:\n")
    correct="secretpassword123"
    tests=[
        ("secretpassword123","Contraseña correcta"),
        ("aaaaaaaaaaaaaaaaaa","Primera letra incorrecta"),
        ("secretpassword124","Última letra incorrecta"),
    ]
    for test_pwd,desc in tests:
        vuln_t =measure_timing(vulnerable_compare,  test_pwd,correct,500)
        safe_t =measure_timing(constant_time_compare,test_pwd,correct,500)
        print(f"  {desc[:35]:<35}")
        print(f"    Vulnerable    : {round(vuln_t):>8} ns  {Fore.RED}← timing leak{Style.RESET_ALL}")
        print(f"    Constant-time : {round(safe_t):>8} ns  {Fore.GREEN}← no leak{Style.RESET_ALL}\n")

def explain_side_channels()->dict:
    return{
        "types":{
            "Timing Attack":{"desc":"Measure execution time to infer secret data",
                              "example":"Password comparison exits early on mismatch",
                              "mitigation":"hmac.compare_digest(), constant-time operations"},
            "Cache Timing (Flush+Reload)":{"desc":"Monitor CPU cache to leak crypto keys",
                              "example":"AES T-table lookups leak key bits (Bernstein 2005)",
                              "mitigation":"Bitsliced implementations, memory barriers"},
            "Power Analysis (SPA/DPA)":{"desc":"Measure CPU power consumption during crypto ops",
                              "example":"RSA square-and-multiply leaks key bits",
                              "mitigation":"Randomized exponent, power balancing"},
            "Spectre/Meltdown":{"desc":"Speculative execution leaks cross-process memory",
                              "example":"Read kernel memory from userspace (2018)",
                              "mitigation":"Kernel page isolation (KPTI), microcode patches"},
            "Rowhammer":{"desc":"Repeated DRAM row access flips bits in adjacent rows",
                          "example":"Privilege escalation via page table corruption",
                          "mitigation":"ECC memory, target row refresh (TRR)"},
        }
    }

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="Side Channel Attack Simulator")
    sub=parser.add_subparsers(dest="cmd")
    sub.add_parser("timing",  help="Demo ataque de timing")
    sub.add_parser("compare", help="Vulnerable vs constant-time comparison")
    sub.add_parser("explain", help="Tipos de ataques de canal lateral")
    args=parser.parse_args()
    if args.cmd=="timing":
        r=timing_attack_demo("s3cr3t")
        print(f"\n  {Fore.CYAN}Resultado: guessed='{r['guessed']}' de '{r['target']}'")
        print(f"  {Fore.YELLOW}Mitigación: usar hmac.compare_digest() siempre{Style.RESET_ALL}")
    elif args.cmd=="compare":
        demonstrate_constant_time()
    elif args.cmd=="explain":
        info=explain_side_channels()
        for name,data in info["types"].items():
            print(f"\n  {Fore.YELLOW}[{name}]{Style.RESET_ALL}")
            for k,v in data.items():print(f"    {k:<12}: {v}")
    else:
        print(f"\n  Comandos: timing, compare, explain")
        print(f"  Ejemplo: python3 19_side_channel.py compare")
if __name__=="__main__":main()

