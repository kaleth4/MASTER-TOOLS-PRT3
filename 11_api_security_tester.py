#!/usr/bin/env python3
"""11 · API SECURITY TESTER — Test REST APIs for auth, IDOR, injection"""

import requests, argparse, json, sys, re, base64
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🔌 API SECURITY TESTER  v1.0        ║\n║  Auth · IDOR · Rate limit · Injection║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def test_auth_bypass(base_url: str, session: requests.Session) -> list:
    findings = []
    protected = ["/admin","/api/admin","/api/users","/api/config",
                  "/api/v1/admin","/dashboard","/management"]
    for path in protected:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=6, verify=False)
            if r.status_code == 200:
                findings.append({"type":"AUTH_BYPASS","level":"CRÍTICO",
                                   "url":url,"status":r.status_code,
                                   "note":"Endpoint protegido accesible sin auth"})
            if r.status_code == 403:
                # Try bypass tricks
                for header, value in [
                    ("X-Original-URL", path),
                    ("X-Rewrite-URL", path),
                    ("X-Custom-IP-Authorization","127.0.0.1"),
                    ("X-Forwarded-For","127.0.0.1"),
                    ("X-Remote-IP","127.0.0.1"),
                ]:
                    r2 = session.get(base_url.rstrip("/")+"/",
                                      headers={header:value}, timeout=5, verify=False)
                    if r2.status_code == 200:
                        findings.append({"type":"HEADER_BYPASS","level":"CRÍTICO",
                                           "url":url,"header":f"{header}: {value}",
                                           "note":"403 bypass via header"})
                        break
        except: pass
    return findings

def test_idor(base_url: str, session: requests.Session, token: str = None) -> list:
    findings = []
    endpoints = ["/api/users/{id}","/api/orders/{id}","/api/profile/{id}",
                  "/api/documents/{id}","/api/accounts/{id}"]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    for endpoint in endpoints:
        for i in range(1, 6):
            url = base_url.rstrip("/") + endpoint.replace("{id}",str(i))
            try:
                r = session.get(url, headers=headers, timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 10:
                    findings.append({"type":"POTENTIAL_IDOR","level":"ALTO",
                                       "url":url,"note":f"Resource {i} accessible"})
            except: pass
    return findings

def test_rate_limiting(base_url: str, session: requests.Session, endpoint: str = "/api/login") -> dict:
    url = base_url.rstrip("/") + endpoint
    results = {"url":url,"requests_sent":0,"responses":{}}
    for i in range(20):
        try:
            r = session.post(url, json={"username":"test","password":"test"},
                              timeout=3, verify=False)
            code = str(r.status_code)
            results["responses"][code] = results["responses"].get(code,0)+1
            results["requests_sent"] += 1
        except: break

    has_429 = "429" in results["responses"]
    results["rate_limited"] = has_429
    results["level"] = "BAJO" if has_429 else "ALTO"
    results["note"] = "Rate limiting implementado" if has_429 else "Sin rate limiting — vulnerable a brute force"
    return results

def test_injection_api(base_url: str, session: requests.Session) -> list:
    findings = []
    payloads = {
        "sql":    ["' OR '1'='1","1 UNION SELECT 1,2,3--","' OR SLEEP(3)--"],
        "nosql":  ['{"$gt":""}','{"$ne":null}','{"$where":"this.password.length>0"}'],
        "xss":    ["<script>alert(1)</script>","<img src=x onerror=alert(1)>"],
        "cmd":    [";ls","&&whoami","|id","$(id)"],
    }
    test_endpoints = ["/api/search","/api/users","/api/products","/api/query"]
    for endpoint in test_endpoints:
        url = base_url.rstrip("/") + endpoint
        for inj_type, plist in payloads.items():
            for payload in plist[:2]:
                try:
                    r = session.get(f"{url}?q={requests.utils.quote(payload)}",
                                     timeout=5, verify=False)
                    body = r.text.lower()
                    errors = ["sql","mysql","syntax error","ora-","mongodb","exception"]
                    if any(e in body for e in errors) and r.status_code != 404:
                        findings.append({"type":f"{inj_type.upper()}_INJECTION",
                                           "level":"CRÍTICO","url":url,
                                           "payload":payload[:50]})
                        break
                except: pass
    return findings

def test_sensitive_data(base_url: str, session: requests.Session) -> list:
    findings = []
    endpoints = ["/api/health","/api/info","/api/debug","/api/env",
                  "/api/metrics","/.well-known/security.txt","/api/swagger.json",
                  "/api/openapi.json","/v1/swagger.json"]
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        try:
            r = session.get(url, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 20:
                sensitive = ["password","secret","key","token","database","connection"]
                found = [s for s in sensitive if s in r.text.lower()]
                if found:
                    findings.append({"type":"SENSITIVE_DISCLOSURE","level":"ALTO",
                                       "url":url,"keywords":found[:3]})
                else:
                    findings.append({"type":"EXPOSED_ENDPOINT","level":"MEDIO",
                                       "url":url,"note":"Endpoint accesible sin auth"})
        except: pass
    return findings

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="API Security Tester")
    parser.add_argument("-u","--url",     required=True)
    parser.add_argument("-t","--token",   default=None)
    parser.add_argument("--skip-injection", action="store_true")
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    base = args.url if args.url.startswith("http") else "https://"+args.url
    session = requests.Session()
    session.headers.update({"User-Agent":"APISecTester/1.0"})
    all_findings = []

    tests = [
        ("Auth Bypass",       lambda: test_auth_bypass(base, session)),
        ("IDOR",              lambda: test_idor(base, session, args.token)),
        ("Rate Limiting",     lambda: [test_rate_limiting(base, session)]),
        ("Sensitive Data",    lambda: test_sensitive_data(base, session)),
    ]
    if not args.skip_injection:
        tests.append(("Injection", lambda: test_injection_api(base, session)))

    for name, fn in tests:
        print(f"\n{Fore.CYAN}[*] Testing: {name}{Style.RESET_ALL}")
        try:
            results = fn()
            for r in results if isinstance(results,list) else [results]:
                all_findings.append(r)
                level = r.get("level","INFO")
                c = Fore.RED if level in ("CRÍTICO","ALTO") else Fore.YELLOW
                print(f"  {c}[{level}]{Style.RESET_ALL} {r.get('type','?')}: "
                      f"{r.get('note',r.get('url',''))[:80]}")
        except Exception as e:
            print(f"  {Fore.GRAY}Error: {e}{Style.RESET_ALL}")

    criticals = len([f for f in all_findings if f.get("level")=="CRÍTICO"])
    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.RED if criticals else Fore.GREEN}Total: {len(all_findings)}  Críticos: {criticals}")
    if args.output:
        with open(args.output,"w") as f: json.dump(all_findings, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
