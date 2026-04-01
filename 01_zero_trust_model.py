#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  01 · ZERO TRUST SECURITY MODEL      ║
║  Simulate & assess Zero Trust posture║
╚══════════════════════════════════════╝
Simula políticas Zero Trust: never trust, always verify.
Usage: python3 01_zero_trust_model.py
"""

import json, argparse, hashlib, time, uuid
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════╗
║  🛡️  ZERO TRUST MODEL  v1.0          ║
║  Never Trust — Always Verify         ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

# ── Zero Trust Pillars ──────────────────────────────────────────
PILLARS = {
    "Identity":    ["MFA enabled","Privileged Access Management","Conditional Access"],
    "Devices":     ["Device compliance check","EDR installed","Patch level current"],
    "Network":     ["Micro-segmentation","Encrypted traffic","No implicit trust"],
    "Applications":["Least privilege access","App-level auth","API security"],
    "Data":        ["Data classification","Encryption at rest","DLP controls"],
}

# ── Simulated users/resources ───────────────────────────────────
USERS = {
    "alice":  {"role":"admin",   "mfa":True,  "device_compliant":True,  "location":"office"},
    "bob":    {"role":"analyst", "mfa":True,  "device_compliant":True,  "location":"remote"},
    "charlie":{"role":"intern",  "mfa":False, "device_compliant":False, "location":"unknown"},
    "dave":   {"role":"analyst", "mfa":True,  "device_compliant":False, "location":"vpn"},
}

RESOURCES = {
    "finance_db":    {"required_role":["admin"],          "sensitivity":"critical"},
    "internal_wiki": {"required_role":["admin","analyst"],"sensitivity":"medium"},
    "public_portal": {"required_role":["admin","analyst","intern"],"sensitivity":"low"},
    "source_code":   {"required_role":["admin","analyst"],"sensitivity":"high"},
}

access_log = []

def evaluate_request(username: str, resource: str) -> dict:
    """Apply Zero Trust policies to an access request."""
    ts     = datetime.now().strftime("%H:%M:%S")
    result = {
        "ts":       ts,
        "user":     username,
        "resource": resource,
        "checks":   [],
        "allowed":  False,
        "risk":     0,
    }

    user = USERS.get(username)
    res  = RESOURCES.get(resource)

    if not user:
        result["checks"].append(("DENY","Unknown user — identity not in directory"))
        access_log.append(result)
        return result

    if not res:
        result["checks"].append(("DENY","Unknown resource"))
        access_log.append(result)
        return result

    # Check 1: Identity — MFA
    if user["mfa"]:
        result["checks"].append(("PASS","MFA verified"))
    else:
        result["checks"].append(("FAIL","MFA not enabled — access denied"))
        result["risk"] += 30
        access_log.append(result)
        return result

    # Check 2: Role authorization
    if user["role"] in res["required_role"]:
        result["checks"].append(("PASS",f"Role '{user['role']}' authorized for '{resource}'"))
    else:
        result["checks"].append(("FAIL",f"Role '{user['role']}' lacks access to '{resource}'"))
        result["risk"] += 40
        access_log.append(result)
        return result

    # Check 3: Device compliance
    if user["device_compliant"]:
        result["checks"].append(("PASS","Device compliance verified"))
    else:
        result["checks"].append(("WARN","Device non-compliant — elevated risk"))
        result["risk"] += 20

    # Check 4: Location risk
    loc_risk = {"office":0,"vpn":10,"remote":15,"unknown":35}
    loc      = user.get("location","unknown")
    risk_pts = loc_risk.get(loc, 35)
    result["risk"] += risk_pts
    if risk_pts > 20:
        result["checks"].append(("WARN",f"High-risk location: {loc}"))
    else:
        result["checks"].append(("PASS",f"Location acceptable: {loc}"))

    # Final decision: allow if risk < 40 and no FAIL
    failed = any(c[0] == "FAIL" for c in result["checks"])
    result["allowed"] = not failed and result["risk"] < 40
    access_log.append(result)
    return result

def assess_organization(config: dict) -> dict:
    """Score an organization's Zero Trust maturity."""
    score  = 0
    total  = 0
    report = {}

    for pillar, controls in PILLARS.items():
        pillar_score = 0
        pillar_cfg   = config.get(pillar, {})
        details      = []
        for control in controls:
            total += 1
            implemented = pillar_cfg.get(control, False)
            if implemented:
                score       += 1
                pillar_score += 1
                details.append(("PASS", control))
            else:
                details.append(("FAIL", control))
        report[pillar] = {"score": pillar_score, "total": len(controls), "details": details}

    maturity = round(score / total * 100) if total > 0 else 0
    level    = ("Nivel 0 — Sin Zero Trust" if maturity < 20 else
                "Nivel 1 — Inicial"        if maturity < 40 else
                "Nivel 2 — Parcial"        if maturity < 60 else
                "Nivel 3 — Avanzado"       if maturity < 80 else
                "Nivel 4 — Optimizado")
    return {"score": score, "total": total, "maturity": maturity,
            "level": level, "pillars": report}

def print_request(r: dict):
    status  = f"{Fore.GREEN}PERMITIDO" if r["allowed"] else f"{Fore.RED}DENEGADO"
    risk_c  = Fore.GREEN if r["risk"] < 20 else Fore.YELLOW if r["risk"] < 40 else Fore.RED
    print(f"\n  {Fore.CYAN}[{r['ts']}]{Style.RESET_ALL} "
          f"{r['user']} → {r['resource']}  "
          f"{status}{Style.RESET_ALL}  "
          f"{risk_c}Risk: {r['risk']}{Style.RESET_ALL}")
    for check_type, msg in r["checks"]:
        icon = f"{Fore.GREEN}✓" if check_type=="PASS" else f"{Fore.RED}✗" if check_type=="FAIL" else f"{Fore.YELLOW}⚠"
        print(f"    {icon}{Style.RESET_ALL} {msg}")

def demo_simulation():
    print(f"\n{Fore.CYAN}[*] Simulando solicitudes de acceso...\n")
    scenarios = [
        ("alice",   "finance_db"),
        ("bob",     "source_code"),
        ("charlie", "internal_wiki"),
        ("dave",    "finance_db"),
        ("alice",   "public_portal"),
        ("unknown_user", "finance_db"),
    ]
    for user, resource in scenarios:
        r = evaluate_request(user, resource)
        print_request(r)

def demo_assessment():
    print(f"\n{Fore.CYAN}[*] Evaluando madurez Zero Trust...\n")
    config = {
        "Identity":    {"MFA enabled":True, "Privileged Access Management":True, "Conditional Access":False},
        "Devices":     {"Device compliance check":True, "EDR installed":False, "Patch level current":True},
        "Network":     {"Micro-segmentation":False, "Encrypted traffic":True, "No implicit trust":False},
        "Applications":{"Least privilege access":True, "App-level auth":True, "API security":False},
        "Data":        {"Data classification":False, "Encryption at rest":True, "DLP controls":False},
    }
    result = assess_organization(config)
    print(f"  {Fore.CYAN}Madurez Zero Trust: {result['maturity']}%")
    print(f"  {Fore.YELLOW}Nivel: {result['level']}\n")
    for pillar, data in result["pillars"].items():
        bar   = "█" * data["score"] + "░" * (data["total"] - data["score"])
        color = Fore.GREEN if data["score"] == data["total"] else Fore.YELLOW if data["score"] > 0 else Fore.RED
        print(f"  {color}{pillar:<15}{Style.RESET_ALL} [{bar}] {data['score']}/{data['total']}")
        for ct, ctrl in data["details"]:
            icon = f"{Fore.GREEN}✓" if ct=="PASS" else f"{Fore.RED}✗"
            print(f"    {icon}{Style.RESET_ALL} {ctrl}")
    return result

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Zero Trust Security Model Simulator")
    parser.add_argument("--simulate",  action="store_true", help="Simular solicitudes de acceso")
    parser.add_argument("--assess",    action="store_true", help="Evaluar madurez Zero Trust")
    parser.add_argument("--request",   nargs=2, metavar=("USER","RESOURCE"))
    parser.add_argument("-o","--output",default=None)
    args = parser.parse_args()

    if args.request:
        r = evaluate_request(args.request[0], args.request[1])
        print_request(r)
    elif args.simulate:
        demo_simulation()
    elif args.assess:
        demo_assessment()
    else:
        demo_simulation()
        demo_assessment()

    if args.output:
        with open(args.output,"w") as f:
            json.dump({"log": access_log}, f, indent=2)
        print(f"\n{Fore.CYAN}[*] Log guardado: {args.output}")

if __name__ == "__main__":
    main()
