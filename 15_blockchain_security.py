#!/usr/bin/env python3
"""15 · BLOCKCHAIN SECURITY ANALYZER — Smart contract & wallet audit"""
import re,json,argparse,hashlib,secrets,base58
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.YELLOW}╔══════════════════════════════════════╗\n║  ⛓️  BLOCKCHAIN SECURITY  v1.0       ║\n║  Smart contract · Wallet audit       ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"
SOLIDITY_VULNS=[
    (r"tx\.origin",                "CRÍTICO","tx.origin auth bypass — use msg.sender"),
    (r"\.call\{value:",            "ALTO",   "Low-level .call — check reentrancy"),
    (r"\.transfer\(",              "MEDIO",  ".transfer() deprecated — use .call{value}"),
    (r"block\.timestamp",          "MEDIO",  "Timestamp manipulation possible by miner"),
    (r"block\.number",             "BAJO",   "Block number predictable — avoid for randomness"),
    (r"keccak256\(.*block",        "ALTO",   "Weak randomness via block hash"),
    (r"selfdestruct|suicide",      "CRÍTICO","selfdestruct — contract can be destroyed"),
    (r"assembly\s*{",              "ALTO",   "Inline assembly — bypass safety checks"),
    (r"delegatecall",              "CRÍTICO","delegatecall — storage collision risk"),
    (r"overflow|underflow",        "CRÍTICO","Arithmetic overflow/underflow mentioned"),
    (r"pragma solidity\s*\^?0\.[0-4]\.", "ALTO","Old Solidity version — use 0.8+"),
    (r"public\s+\w+\s*=",         "MEDIO",  "Public state variable — may expose sensitive data"),
    (r"mapping.*address.*=>.*uint","BAIXO",  "Mapping to uint — check for reentrancy if eth"),
]
def analyze_solidity(code:str)->list:
    findings=[]
    for pattern,level,desc in SOLIDITY_VULNS:
        for m in re.finditer(pattern,code,re.IGNORECASE|re.MULTILINE):
            line=code[:m.start()].count("\n")+1
            findings.append({"level":level,"line":line,"pattern":pattern[:30],"desc":desc})
    # Check for missing modifiers
    if "onlyOwner" not in code and "require(msg.sender" not in code:
        findings.append({"level":"ALTO","line":0,"desc":"No access control detected — any address can call functions"})
    if "ReentrancyGuard" not in code and ".call{value:" in code:
        findings.append({"level":"CRÍTICO","line":0,"desc":"Potential reentrancy — no ReentrancyGuard"})
    return findings
def check_wallet_address(address:str)->dict:
    result={"address":address,"type":"unknown","valid":False,"issues":[]}
    # Ethereum
    if re.match(r"^0x[0-9a-fA-F]{40}$",address):
        result["type"]="Ethereum/ERC-20"
        result["valid"]=True
        # Check EIP-55 checksum
        hex_addr=address[2:]
        checksum=hashlib.sha3_256(hex_addr.lower().encode()).hexdigest()
        expected="0x"+"".join(c.upper() if int(checksum[i],16)>=8 else c for i,c in enumerate(hex_addr.lower()))
        if address!=expected and address.lower()!=address and address.upper()[2:]!=hex_addr.upper():
            result["issues"].append({"level":"MEDIO","msg":"Address checksum invalid — may be typo"})
        if "000000" in hex_addr.lower():
            result["issues"].append({"level":"BAJO","msg":"Address contains zero-padding — verify"})
    # Bitcoin
    elif re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",address):
        result["type"]="Bitcoin (Legacy P2PKH/P2SH)"
        result["valid"]=True
    elif re.match(r"^bc1[a-z0-9]{39,59}$",address):
        result["type"]="Bitcoin (Bech32/SegWit)"
        result["valid"]=True
    elif re.match(r"^[13456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,62}$",address):
        result["type"]="Possible Solana/BSC/other"
        result["valid"]=True
    # Common scam patterns
    scam_patterns=["0x0000000000000000000000000000000000000000","0xdEaD"]
    if any(s.lower() in address.lower() for s in scam_patterns):
        result["issues"].append({"level":"CRÍTICO","msg":"Known burn/zero address — do not send funds"})
    return result
def generate_eth_vanity_info(prefix:str="")->dict:
    """Educational demo of address generation (not secure for real use)."""
    private_key=secrets.token_hex(32)
    # Simplified address derivation (demo only - not cryptographically correct)
    pub_hash=hashlib.sha3_256(bytes.fromhex(private_key)).hexdigest()
    address="0x"+pub_hash[-40:]
    return {"private_key_demo":private_key,"address":address,
            "warning":"DEMO ONLY — use proper tools like MetaMask for real wallets",
            "entropy_bits":256,"recommendation":"Use hardware wallet (Ledger/Trezor) for real funds"}
def demo_contract_analysis()->None:
    vulnerable_contract="""
pragma solidity ^0.6.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    address owner;
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State change AFTER external call = REENTRANCY
    }
    
    function transfer(address to, uint amount) public {
        require(tx.origin == owner);  // tx.origin auth bypass
        balances[to] += amount;
    }
    
    function random() public view returns(uint) {
        return keccak256(abi.encode(block.timestamp, block.number));  // Weak randomness
    }
    
    function destroy() public {
        selfdestruct(payable(owner));
    }
}"""
    print(f"\n{Fore.CYAN}[*] Analizando contrato Solidity de ejemplo...\n")
    findings=analyze_solidity(vulnerable_contract)
    print(f"  {Fore.YELLOW}Contrato 'Vulnerable.sol' — {len(findings)} hallazgos:{Style.RESET_ALL}\n")
    for f in findings:
        c=Fore.RED if f["level"]=="CRÍTICO" else Fore.YELLOW if f["level"]=="ALTO" else Fore.MAGENTA
        line=f" (línea {f['line']})" if f.get("line") else ""
        print(f"  {c}[{f['level']}]{Style.RESET_ALL}{line} {f['desc']}")
def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="Blockchain Security Analyzer")
    sub=parser.add_subparsers(dest="cmd")
    sub.add_parser("demo",help="Demo análisis contrato vulnerable")
    w_p=sub.add_parser("wallet",help="Verificar dirección wallet")
    w_p.add_argument("address")
    s_p=sub.add_parser("contract",help="Analizar archivo Solidity")
    s_p.add_argument("file")
    s_p.add_argument("-o","--output",default=None)
    args=parser.parse_args()
    if args.cmd=="wallet":
        r=check_wallet_address(args.address)
        print(f"\n  Dirección: {r['address']}")
        print(f"  Tipo     : {Fore.CYAN}{r['type']}{Style.RESET_ALL}")
        print(f"  Válida   : {Fore.GREEN if r['valid'] else Fore.RED}{r['valid']}{Style.RESET_ALL}")
        for issue in r["issues"]:
            c=Fore.RED if issue["level"]=="CRÍTICO" else Fore.YELLOW
            print(f"  {c}[{issue['level']}]{Style.RESET_ALL} {issue['msg']}")
    elif args.cmd=="contract":
        import os
        if not os.path.isfile(args.file):
            print(f"{Fore.RED}[✗] Archivo no encontrado"); return
        with open(args.file) as f:code=f.read()
        findings=analyze_solidity(code)
        for f2 in findings:
            c=Fore.RED if f2["level"]=="CRÍTICO" else Fore.YELLOW
            print(f"  {c}[{f2['level']}] Line {f2.get('line',0)}: {f2['desc']}{Style.RESET_ALL}")
        if args.output:
            with open(args.output,"w") as f3:json.dump(findings,f3,indent=2)
    else:
        demo_contract_analysis()
if __name__=="__main__":main()
