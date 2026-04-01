#!/usr/bin/env python3
"""16 · SCADA/ICS SECURITY SCANNER — Industrial control system assessment"""
import socket,argparse,json,struct,concurrent.futures
from colorama import Fore,Style,init
init(autoreset=True)
BANNER=f"{Fore.RED}╔══════════════════════════════════════╗\n║  🏭 SCADA/ICS SECURITY  v1.0         ║\n║  Modbus · DNP3 · ICS protocol check  ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"
ICS_PORTS={
    502:"Modbus TCP (PLC/RTU)",
    20000:"DNP3 (SCADA protocol)",
    44818:"EtherNet/IP (Allen-Bradley)",
    102:"S7 (Siemens STEP 7)",
    4840:"OPC UA",
    2222:"EtherNet/IP discovery",
    47808:"BACnet (Building automation)",
    1911:"Niagara Fox (HVAC/BAS)",
    4000:"Emerson DeltaV",
    9600:"Omron FINS",
    18245:"GE SRTP",
    34980:"Schweitzer SEL",
}
def check_modbus(ip:str,port:int=502)->dict:
    """Send Modbus read coils request and check response."""
    try:
        with socket.create_connection((ip,port),timeout=3) as s:
            # Modbus TCP: Transaction ID=1, Protocol=0, Length=6, Unit=1, FC=1, Addr=0, Count=8
            request=struct.pack(">HHHBBHH",0x0001,0x0000,0x0006,0x01,0x01,0x0000,0x0008)
            s.sendall(request)
            response=s.recv(256)
            if len(response)>=6:
                func_code=response[7] if len(response)>7 else 0
                if func_code==0x01:
                    return{"open":True,"protocol":"Modbus TCP","level":"CRÍTICO",
                           "response_bytes":len(response),
                           "note":"Modbus responde sin autenticación — acceso a coils/registros"}
                elif func_code==0x81:
                    return{"open":True,"protocol":"Modbus TCP","level":"ALTO",
                           "note":"Modbus activo (error en función)"}
            return{"open":True,"protocol":"Modbus TCP","level":"ALTO","note":"Puerto abierto"}
    except ConnectionRefusedError:
        return{"open":False}
    except:
        return{"open":False}
def check_dnp3(ip:str,port:int=20000)->dict:
    try:
        with socket.create_connection((ip,port),timeout=3) as s:
            return{"open":True,"protocol":"DNP3","level":"CRÍTICO",
                   "note":"DNP3 expuesto — protocolo SCADA sin cifrado en versiones antiguas"}
    except:return{"open":False}
def check_s7(ip:str,port:int=102)->dict:
    """Check for Siemens S7 PLC (COTP connection request)."""
    try:
        with socket.create_connection((ip,port),timeout=3) as s:
            # COTP connection request
            cotp=bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,
                        0x00,0x01,0x00,0xc0,0x01,0x0a,0xc1,0x02,
                        0x01,0x00,0xc2,0x02,0x01,0x02])
            s.sendall(cotp)
            resp=s.recv(64)
            if resp and len(resp)>4:
                return{"open":True,"protocol":"Siemens S7","level":"CRÍTICO",
                       "note":"PLC Siemens S7 detectado — acceso potencial sin auth","response":resp.hex()[:20]}
    except:pass
    return{"open":False}
def check_bacnet(ip:str,port:int=47808)->dict:
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.settimeout(3)
        # BACnet Who-Is request
        whois=bytes([0x81,0x0a,0x00,0x08,0x01,0x20,0xff,0xff])
        sock.sendto(whois,(ip,port))
        data,addr=sock.recvfrom(256)
        if data:
            return{"open":True,"protocol":"BACnet","level":"ALTO",
                   "note":"BACnet sistema de automatización de edificios — acceso a HVAC/control"}
    except:pass
    finally:
        try:sock.close()
        except:pass
    return{"open":False}
def ics_risk_assessment(findings:list)->str:
    if not findings:return "BAJO"
    levels=[f.get("level","BAJO") for f in findings]
    if "CRÍTICO" in levels:return "CRÍTICO"
    if "ALTO" in levels:return "ALTO"
    return "MEDIO"
def explain_ics_risks()->None:
    risks={
        "Modbus TCP":{"risk":"CRÍTICO","desc":"Sin autenticación ni cifrado. Permite leer/escribir directamente en PLCs.",
                      "impact":"Apagado de equipos industriales, sabotaje de procesos",
                      "real_attack":"Stuxnet (Siemens S7), German steel mill attack 2014"},
        "DNP3":{"risk":"CRÍTICO","desc":"Protocolo SCADA sin cifrado en v2/v3.",
                "impact":"Manipulación de RTUs en redes eléctricas, agua, gas",
                "real_attack":"Ukraine power grid attack 2015 (BlackEnergy)"},
        "Siemens S7":{"risk":"CRÍTICO","desc":"PLCs industriales con acceso directo por red.",
                      "impact":"Control físico de maquinaria — daño irreversible",
                      "real_attack":"Stuxnet 2010 — centrifugas nucleares iraníes"},
        "BACnet":{"risk":"ALTO","desc":"Automatización de edificios — HVAC, control de acceso.",
                  "impact":"Control de temperatura, alarmas, puertas inteligentes",
                  "real_attack":"Target HVAC breach 2013 — 40M tarjetas robadas"},
    }
    for proto,info in risks.items():
        c=Fore.RED if info["risk"]=="CRÍTICO" else Fore.YELLOW
        print(f"\n  {c}[{info['risk']}] {proto}{Style.RESET_ALL}")
        print(f"    Desc    : {info['desc']}")
        print(f"    Impacto : {info['impact']}")
        print(f"    Ataque  : {Fore.YELLOW}{info['real_attack']}{Style.RESET_ALL}")
def scan_ics_target(ip:str)->dict:
    result={"ip":ip,"findings":[],"risk":"BAJO"}
    checks=[(check_modbus,ip,502),(check_dnp3,ip,20000),(check_s7,ip,102),(check_bacnet,ip,47808)]
    for fn,*args in checks:
        r=fn(*args)
        if r.get("open"):result["findings"].append(r)
    # Check other ICS ports
    for port,service in ICS_PORTS.items():
        if port in(502,20000,102,47808):continue
        try:
            with socket.create_connection((ip,port),timeout=1):
                result["findings"].append({"open":True,"protocol":service,"port":port,"level":"ALTO",
                                            "note":f"Puerto ICS {port} accesible"})
        except:pass
    result["risk"]=ics_risk_assessment(result["findings"])
    return result
def main():
    print(BANNER)
    print(f"{Fore.RED}⚠  SOLO en entornos autorizados — ICS comprometido = impacto físico real{Style.RESET_ALL}\n")
    parser=argparse.ArgumentParser(description="SCADA/ICS Security Scanner")
    sub=parser.add_subparsers(dest="cmd")
    sc_p=sub.add_parser("scan",help="Escanear objetivo ICS")
    sc_p.add_argument("-t","--target",required=True)
    sc_p.add_argument("-o","--output",default=None)
    sub.add_parser("explain",help="Explicar riesgos ICS")
    args=parser.parse_args()
    if args.cmd=="explain":
        explain_ics_risks()
    elif args.cmd=="scan":
        print(f"{Fore.CYAN}[*] Escaneando ICS target: {args.target}\n")
        r=scan_ics_target(args.target)
        risk_c=Fore.RED if r["risk"]=="CRÍTICO" else Fore.YELLOW if r["risk"]=="ALTO" else Fore.GREEN
        print(f"  {Fore.CYAN}IP    : {r['ip']}")
        print(f"  {risk_c}Riesgo: {r['risk']}{Style.RESET_ALL}")
        if r["findings"]:
            print(f"\n  {Fore.RED}Protocolos ICS encontrados:{Style.RESET_ALL}")
            for f in r["findings"]:
                c=Fore.RED if f.get("level")=="CRÍTICO" else Fore.YELLOW
                print(f"  {c}[{f.get('level','?')}]{Style.RESET_ALL} {f.get('protocol','?')}: {f.get('note','')}")
        else:
            print(f"  {Fore.GREEN}Sin protocolos ICS expuestos detectados")
        if args.output:
            with open(args.output,"w") as f2:json.dump(r,f2,indent=2)
            print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")
    else:
        print("  Comandos: scan -t IP, explain")
if __name__=="__main__":main()
