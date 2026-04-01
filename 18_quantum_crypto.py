#!/usr/bin/env python3
"""18 · QUANTUM CRYPTOGRAPHY BASICS — Simulate BB84 and post-quantum concepts"""
import random,secrets,math,argparse
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.MAGENTA}╔══════════════════════════════════════╗\n║  ⚛️  QUANTUM CRYPTO  v1.0             ║\n║  BB84 · Post-quantum · Shor sim      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def bb84_simulation(key_length:int=20,eavesdrop:bool=False)->dict:
    """Simulate BB84 Quantum Key Distribution protocol."""
    # Alice generates random bits and bases
    alice_bits  =[random.randint(0,1) for _ in range(key_length*3)]
    alice_bases =[random.choice(['+','x']) for _ in range(key_length*3)]
    
    # Simulate quantum channel
    bob_bases=[random.choice(['+','x']) for _ in range(key_length*3)]
    
    # Eve intercepts (if eavesdropping)
    eve_bases=[random.choice(['+','x']) for _ in range(key_length*3)] if eavesdrop else []
    
    # Bob measures qubits
    bob_bits=[]
    for i in range(len(alice_bits)):
        if alice_bases[i]==bob_bases[i]:
            bob_bits.append(alice_bits[i])
        else:
            bob_bits.append(random.randint(0,1))  # Random when bases mismatch
    
    # Sifting: keep only matching bases
    alice_key=[]
    bob_key=[]
    for i in range(len(alice_bits)):
        if alice_bases[i]==bob_bases[i]:
            alice_key.append(alice_bits[i])
            bob_key.append(bob_bits[i])
        if len(alice_key)>=key_length:break
    
    alice_key=alice_key[:key_length]
    bob_key=bob_key[:key_length]
    
    # Error rate (Eve causes ~25% errors when eavesdropping)
    errors=sum(1 for a,b in zip(alice_key,bob_key) if a!=b)
    error_rate=errors/len(alice_key) if alice_key else 0
    
    # Threshold: if QBER > 11%, eavesdropping likely
    eavesdrop_detected=error_rate>0.11
    
    return{
        "protocol":"BB84","key_length":len(alice_key),
        "alice_key":"".join(map(str,alice_key)),
        "bob_key":  "".join(map(str,bob_key)),
        "keys_match":alice_key==bob_key,
        "error_rate":round(error_rate*100,1),
        "qber_threshold":11.0,
        "eavesdrop_simulated":eavesdrop,
        "eavesdrop_detected":eavesdrop_detected,
    }

def shor_simulation(n:int=15)->dict:
    """Simulate Shor's algorithm concept (classical simulation for small numbers)."""
    # Find factors of n (simplified - not true quantum)
    def find_period(a,n):
        r=1
        x=a%n
        while x!=1 and r<1000:
            x=(x*a)%n
            r+=1
        return r
    
    def gcd(a,b):
        while b:a,b=b,a%b
        return a
    
    factors=[]
    for a in range(2,min(n,20)):
        if gcd(a,n)==1:
            r=find_period(a,n)
            if r%2==0:
                p=gcd(a**(r//2)-1,n)
                q=gcd(a**(r//2)+1,n)
                if 1<p<n and p*q==n:
                    factors=[p,q]
                    break
    
    return{
        "algorithm":"Shor's Algorithm (Classical Simulation)",
        "input":n,
        "factors":factors if factors else "Not found in simulation",
        "note":"On real quantum computer, would factor in polynomial time",
        "threat_to":"RSA, DSA, ECDSA — all based on factoring/discrete log",
        "safe_alternatives":["Kyber (CRYSTALS-Kyber)","Dilithium","FALCON","SPHINCS+"],
    }

def post_quantum_comparison()->list:
    algorithms=[
        {"name":"RSA-2048","type":"Classical","quantum_safe":False,
         "key_size_bits":2048,"note":"Broken by Shor's in O(n³) on quantum computer","status":"Legacy"},
        {"name":"ECDSA-256","type":"Classical","quantum_safe":False,
         "key_size_bits":256,"note":"Broken by Shor's algorithm","status":"Legacy"},
        {"name":"CRYSTALS-Kyber","type":"Post-Quantum","quantum_safe":True,
         "key_size_bits":1568,"note":"NIST selected — lattice-based KEM","status":"NIST Standard 2024"},
        {"name":"CRYSTALS-Dilithium","type":"Post-Quantum","quantum_safe":True,
         "key_size_bits":2528,"note":"NIST selected — lattice-based signatures","status":"NIST Standard 2024"},
        {"name":"FALCON","type":"Post-Quantum","quantum_safe":True,
         "key_size_bits":1281,"note":"NIST selected — NTRU lattice signatures","status":"NIST Standard 2024"},
        {"name":"SPHINCS+","type":"Post-Quantum","quantum_safe":True,
         "key_size_bits":8080,"note":"NIST selected — hash-based signatures","status":"NIST Standard 2024"},
        {"name":"AES-256","type":"Symmetric","quantum_safe":True,
         "key_size_bits":256,"note":"Grover halves effective key size (128-bit security remains)","status":"Quantum-safe"},
        {"name":"SHA-3/256","type":"Hash","quantum_safe":True,
         "key_size_bits":256,"note":"Grover reduces to 128-bit security — still safe","status":"Quantum-safe"},
    ]
    return algorithms

def harvest_now_decrypt_later()->dict:
    """Explain HNDL attack."""
    return{
        "attack":"Harvest Now Decrypt Later (HNDL)",
        "description":"Adversaries capture encrypted traffic today to decrypt when quantum computers are available",
        "timeline_risk":"~2030-2035 (NIST estimate for 'cryptographically relevant quantum computer')",
        "affected_data":["Government secrets","Medical records","Financial transactions","IP/trade secrets"],
        "mitigation":["Migrate to post-quantum algorithms NOW","Hybrid classical+PQC schemes","Perfect Forward Secrecy","Data minimization"],
        "urgency":"ALTA — data encrypted today must be protected for 10-20 years",
    }

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="Quantum Cryptography Basics")
    sub=parser.add_subparsers(dest="cmd")
    bb_p=sub.add_parser("bb84",help="Simular BB84 QKD")
    bb_p.add_argument("-n","--length",type=int,default=20)
    bb_p.add_argument("--eve",action="store_true",help="Simular espionaje")
    sub.add_parser("shor",help="Simular algoritmo de Shor")
    sub.add_parser("pqc",  help="Comparar algoritmos post-quantum")
    sub.add_parser("hndl", help="Explicar ataque Harvest Now Decrypt Later")
    args=parser.parse_args()
    if args.cmd=="bb84":
        print(f"\n{Fore.CYAN}[*] Simulando BB84 QKD (key_length={args.length},eavesdrop={args.eve})\n")
        r=bb84_simulation(args.length,args.eve)
        print(f"  Alice key : {Fore.GREEN}{r['alice_key']}{Style.RESET_ALL}")
        print(f"  Bob key   : {Fore.GREEN if r['keys_match'] else Fore.RED}{r['bob_key']}{Style.RESET_ALL}")
        print(f"  Keys match: {r['keys_match']}")
        print(f"  QBER      : {r['error_rate']}% (threshold: {r['qber_threshold']}%)")
        if args.eve:
            det=r["eavesdrop_detected"]
            print(f"  Eve detect: {Fore.RED if det else Fore.GREEN}{det}{Style.RESET_ALL}")
            if det:print(f"  {Fore.RED}→ QBER alto — canal comprometido, descartar clave{Style.RESET_ALL}")
    elif args.cmd=="shor":
        r=shor_simulation(15)
        print(f"\n  {Fore.CYAN}Factorizando N=15...{Style.RESET_ALL}")
        for k,v in r.items():print(f"  {k:<20}: {v}")
    elif args.cmd=="pqc":
        algs=post_quantum_comparison()
        print(f"\n  {'Algoritmo':<25} {'Tipo':<15} {'Q-Safe':<8} {'Bits':<8} {'Estado'}")
        print(f"  {'─'*80}")
        for a in algs:
            qs=a["quantum_safe"]
            c=Fore.GREEN if qs else Fore.RED
            print(f"  {a['name']:<25} {a['type']:<15} {c}{'✓' if qs else '✗'}{Style.RESET_ALL}      {a['key_size_bits']:<8} {a['status']}")
    elif args.cmd=="hndl":
        r=harvest_now_decrypt_later()
        for k,v in r.items():
            if isinstance(v,list):
                print(f"\n  {Fore.CYAN}{k}:{Style.RESET_ALL}")
                for item in v:print(f"    • {item}")
            else:
                print(f"  {Fore.CYAN}{k:<20}{Style.RESET_ALL}: {v}")
    else:
        print("  Comandos: bb84 [--eve], shor, pqc, hndl")
        print("  Ejemplo: python3 18_quantum_crypto.py bb84 --eve")

if __name__=="__main__":main()
