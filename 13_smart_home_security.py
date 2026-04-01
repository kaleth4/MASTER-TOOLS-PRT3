#!/usr/bin/env python3
"""13 · SMART HOME SECURITY TESTER — IoT device vulnerability assessment"""

import socket, requests, argparse, json, re, concurrent.futures
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🏠 SMART HOME SECURITY  v1.0        ║\n║  IoT device discovery & assessment   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

# Common IoT default credentials
DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","12345"),
    ("admin","1234"),("root","root"),("root","admin"),
    ("admin",""),("admin","admin123"),("user","user"),
    ("admin","pass"),("support","support"),("guest","guest"),
]

# IoT-specific ports
IOT_PORTS = {
    80:    "HTTP (Web interface)",
    443:   "HTTPS (Secure web interface)",
    23:    "Telnet (CRÍTICO — plaintext)",
    22:    "SSH",
    554:   "RTSP (IP Camera streaming)",
    8080:  "HTTP Alt (Web interface)",
    8443:  "HTTPS Alt",
    1883:  "MQTT (IoT messaging)",
    8883:  "MQTT over TLS",
    5683:  "CoAP (IoT protocol)",
    9100:  "Printer",
    515:   "LPD (Print server)",
    5353:  "mDNS (Device discovery)",
    1900:  "UPnP (Universal Plug and Play)",
    49152: "UPnP HTTP",
    8008:  "Chromecast HTTP",
    8009:  "Chromecast HTTPS",
    9000:  "Synology/NAS",
    5000:  "Synology/NAS",
    7547:  "TR-069 (ISP remote mgmt — CRÍTICO)",
    37777: "Dahua NVR",
    34567: "CCTV DVR",
}

DEVICE_FINGERPRINTS = [
    ("Hikvision",  ["hikvision","hikv"]),
    ("Dahua",      ["dahua","dav"]),
    ("D-Link",     ["d-link","dlink"]),
    ("TP-Link",    ["tp-link","tplink"]),
    ("Netgear",    ["netgear"]),
    ("Linksys",    ["linksys","cisco-linksys"]),
    ("Ubiquiti",   ["ubiquiti","unifi"]),
    ("Arlo",       ["arlo"]),
    ("Ring",       ["ring"]),
    ("Nest",       ["nest"]),
    ("Philips Hue",["philips","hue bridge"]),
    ("Sonos",      ["sonos"]),
    ("Samsung SmartThings",["smartthings"]),
    ("Generic DVR",["dvr","nvr","ipc"]),
    ("Router",     ["router","gateway","dsl"]),
]

def fingerprint_device(banner: str, headers: dict = None) -> str:
    text = (banner + " " + str(headers)).lower()
    for device, keywords in DEVICE_FINGERPRINTS:
        if any(kw in text for kw in keywords):
            return device
    return "Unknown IoT Device"

def check_default_creds_http(ip: str, port: int = 80) -> list:
    scheme  = "https" if port in (443, 8443) else "http"
    base    = f"{scheme}://{ip}:{port}"
    found   = []
    login_paths = ["/login","/signin","/admin","/index.html","/"]
    for user, passwd in DEFAULT_CREDS[:8]:  # limit to first 8
        for path in login_paths[:3]:
            try:
                r = requests.get(f"{base}{path}", auth=(user,passwd),
                                  timeout=4, verify=False)
                if r.status_code == 200 and "login" not in r.url.lower():
                    found.append({"user":user,"password":passwd,
                                   "url":f"{base}{path}","level":"CRÍTICO"})
                    return found
            except: pass
    return found

def check_telnet(ip: str, port: int = 23) -> dict:
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            banner = s.recv(512).decode(errors="replace")
            return {"open":True,"banner":banner[:100],"level":"CRÍTICO",
                    "note":"Telnet expuesto — credenciales sin cifrar"}
    except:
        return {"open":False}

def check_mqtt(ip: str, port: int = 1883) -> dict:
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            # Send MQTT CONNECT packet (no auth)
            connect = bytes([
                0x10,0x12,  # CONNECT, length 18
                0x00,0x04,  # Protocol name length
                0x4d,0x51,0x54,0x54,  # MQTT
                0x04,       # Protocol level 4
                0x00,       # Connect flags (no auth)
                0x00,0x3c,  # Keep alive 60s
                0x00,0x04,  # Client ID length
                0x74,0x65,0x73,0x74,  # "test"
            ])
            s.sendall(connect)
            response = s.recv(4)
            if len(response) >= 4 and response[3] == 0:  # CONNACK = 0 (accepted)
                return {"open":True,"auth_required":False,"level":"CRÍTICO",
                        "note":"MQTT sin autenticación — cualquiera puede suscribirse"}
            return {"open":True,"auth_required":True,"level":"BAJO"}
    except:
        return {"open":False}

def check_upnp(ip: str) -> dict:
    try:
        r = requests.get(f"http://{ip}:1900/rootDesc.xml", timeout=4, verify=False)
        if r.status_code == 200 and "xml" in r.headers.get("content-type","").lower():
            device_type = re.search(r"<deviceType>(.*?)</deviceType>", r.text)
            friendly    = re.search(r"<friendlyName>(.*?)</friendlyName>", r.text)
            return {"open":True,
                    "device_type": device_type.group(1) if device_type else "?",
                    "friendly_name":friendly.group(1) if friendly else "?",
                    "level":"MEDIO",
                    "note":"UPnP expuesto — información de dispositivo visible"}
    except: pass
    return {"open":False}

def scan_iot_device(ip: str) -> dict:
    result = {"ip":ip,"open_ports":{},"device":"?","findings":[]}
    def probe(port):
        try:
            with socket.create_connection((ip,port), timeout=1.5):
                return port
        except: return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(probe,p):p for p in IOT_PORTS}
        for f in concurrent.futures.as_completed(futures):
            p = f.result()
            if p:
                result["open_ports"][p] = IOT_PORTS[p]

    # Fingerprint device
    if 80 in result["open_ports"] or 8080 in result["open_ports"]:
        port = 80 if 80 in result["open_ports"] else 8080
        try:
            r = requests.get(f"http://{ip}:{port}", timeout=4, verify=False)
            result["device"] = fingerprint_device(r.text, dict(r.headers))
            result["web_title"] = re.search(r"<title>(.*?)</title>",r.text,re.I)
            if result["web_title"]: result["web_title"] = result["web_title"].group(1)[:50]
        except: pass

    # Security checks
    if 23 in result["open_ports"]:
        r = check_telnet(ip)
        if r["open"]: result["findings"].append(r)

    if 1883 in result["open_ports"]:
        r = check_mqtt(ip)
        if r["open"]: result["findings"].append({**r,"service":"MQTT"})

    upnp = check_upnp(ip)
    if upnp["open"]: result["findings"].append(upnp)

    if any(p in result["open_ports"] for p in [80,8080,443,8443]):
        port = next(p for p in [80,8080,443,8443] if p in result["open_ports"])
        creds = check_default_creds_http(ip, port)
        result["findings"].extend(creds)

    return result

def print_result(r: dict):
    print(f"\n  {Fore.CYAN}IP     : {r['ip']}{Style.RESET_ALL}")
    print(f"  Device : {Fore.YELLOW}{r['device']}{Style.RESET_ALL}")
    if r.get("web_title"):
        print(f"  Title  : {r['web_title']}")
    if r["open_ports"]:
        print(f"  {Fore.CYAN}Puertos abiertos:{Style.RESET_ALL}")
        for port, service in sorted(r["open_ports"].items()):
            risk = port in (23, 7547, 1883)
            c = Fore.RED if risk else Fore.GREEN
            print(f"    {c}{port:6}{Style.RESET_ALL} {service}")
    if r["findings"]:
        print(f"  {Fore.RED}Hallazgos:{Style.RESET_ALL}")
        for f in r["findings"]:
            level = f.get("level","MEDIO")
            c = Fore.RED if level=="CRÍTICO" else Fore.YELLOW
            note = f.get("note", f.get("user","") + ":" + f.get("password",""))
            print(f"    {c}[{level}]{Style.RESET_ALL} {note}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Smart Home Security Tester")
    parser.add_argument("-t","--target",  help="IP o rango CIDR")
    parser.add_argument("--demo",         action="store_true")
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    if args.demo:
        print(f"\n{Fore.YELLOW}[!] Demo mode — sin escaneo real\n")
        demo = {
            "ip":"192.168.1.100","device":"Hikvision IP Camera",
            "web_title":"IPCamera Login",
            "open_ports":{80:"HTTP",554:"RTSP",23:"Telnet (CRÍTICO)",1883:"MQTT"},
            "findings":[
                {"level":"CRÍTICO","note":"Telnet expuesto sin cifrado","open":True},
                {"level":"CRÍTICO","note":"MQTT sin autenticación","open":True},
                {"level":"CRÍTICO","user":"admin","password":"12345","url":"http://192.168.1.100/login"},
            ]
        }
        print_result(demo)
        return

    if not args.target:
        args.target = input(f"{Fore.CYAN}IP objetivo: {Style.RESET_ALL}").strip()

    print(f"\n{Fore.CYAN}[*] Escaneando: {args.target}\n")
    result = scan_iot_device(args.target)
    print_result(result)

    if args.output:
        with open(args.output,"w") as f: json.dump(result, f, indent=2)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
