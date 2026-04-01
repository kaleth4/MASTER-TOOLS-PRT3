#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  03 · PKI CERTIFICATE MANAGER        ║
║  Generate, inspect & verify certs    ║
╚══════════════════════════════════════╝
Public Key Infrastructure: CA, certs, keys.
Usage: python3 03_pki_manager.py
"""

import os, sys, argparse, json
from datetime import datetime, timezone, timedelta
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════╗
║  🔑 PKI CERTIFICATE MANAGER  v1.0   ║
║  CA · Certificates · Key Management  ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

def require_crypto():
    if not CRYPTO_OK:
        print(f"{Fore.RED}[✗] pip install cryptography"); sys.exit(1)

def generate_key(bits: int = 2048) -> "rsa.RSAPrivateKey":
    return rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )

def save_key(key, path: str, password: str = None):
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    with open(path,"wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, enc
        ))

def save_cert(cert, path: str):
    with open(path,"wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_ca(cn: str, days: int, bits: int, out_dir: str) -> tuple:
    require_crypto()
    os.makedirs(out_dir, exist_ok=True)
    key  = generate_key(bits)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberToolkit CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CO"),
    ])
    now  = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    key_path  = os.path.join(out_dir, "ca.key")
    cert_path = os.path.join(out_dir, "ca.crt")
    save_key(key, key_path)
    save_cert(cert, cert_path)
    print(f"{Fore.GREEN}[✓] CA generada:")
    print(f"    Key : {key_path}")
    print(f"    Cert: {cert_path}")
    print(f"    CN  : {cn}  Válida: {days} días")
    return key, cert

def generate_server_cert(cn: str, ca_key, ca_cert, days: int, bits: int,
                          out_dir: str, sans: list = None):
    require_crypto()
    os.makedirs(out_dir, exist_ok=True)
    key  = generate_key(bits)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberToolkit"),
    ])
    now  = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    )
    # SANs
    san_list = [x509.DNSName(cn)]
    if sans:
        for s in sans:
            san_list.append(x509.DNSName(s))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_list), critical=False
    )
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

    safe_cn   = cn.replace("*","wildcard").replace(".","_")
    key_path  = os.path.join(out_dir, f"{safe_cn}.key")
    cert_path = os.path.join(out_dir, f"{safe_cn}.crt")
    save_key(key, key_path)
    save_cert(cert, cert_path)
    print(f"{Fore.GREEN}[✓] Certificado de servidor generado:")
    print(f"    Key : {key_path}")
    print(f"    Cert: {cert_path}")
    print(f"    CN  : {cn}  SANs: {[s.value for s in san_list]}")

def inspect_cert(cert_path: str) -> dict:
    require_crypto()
    with open(cert_path,"rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    now   = datetime.now(timezone.utc)
    exp   = cert.not_valid_after_utc if hasattr(cert,"not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    nva   = cert.not_valid_before_utc if hasattr(cert,"not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    days_left = (exp - now).days

    issues = []
    if days_left < 0:
        issues.append(("CRÍTICO", "Certificado EXPIRADO"))
    elif days_left < 30:
        issues.append(("ALTO", f"Expira en {days_left} días"))
    elif days_left < 90:
        issues.append(("MEDIO", f"Expira en {days_left} días — renovar pronto"))

    # Check key size
    pub_key = cert.public_key()
    key_size = pub_key.key_size if hasattr(pub_key,"key_size") else 0
    if key_size < 2048:
        issues.append(("CRÍTICO", f"Clave débil: {key_size} bits (mínimo 2048)"))

    # Check signature algorithm
    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
    if sig_alg in ("md5","sha1"):
        issues.append(("CRÍTICO", f"Algoritmo de firma débil: {sig_alg.upper()}"))

    info = {
        "path":       cert_path,
        "subject":    cert.subject.rfc4514_string(),
        "issuer":     cert.issuer.rfc4514_string(),
        "serial":     hex(cert.serial_number),
        "not_before": str(nva)[:19],
        "not_after":  str(exp)[:19],
        "days_left":  days_left,
        "key_size":   key_size,
        "sig_alg":    sig_alg,
        "is_ca":      False,
        "issues":     issues,
    }
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        info["is_ca"] = bc.value.ca
    except: pass

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["sans"] = [s.value for s in san.value]
    except:
        info["sans"] = []

    return info

def print_cert_info(info: dict):
    days = info["days_left"]
    days_c = Fore.GREEN if days > 90 else Fore.YELLOW if days > 30 else Fore.RED
    print(f"\n  {Fore.CYAN}Sujeto  : {info['subject']}")
    print(f"  {Fore.CYAN}Emisor  : {info['issuer']}")
    print(f"  {Fore.CYAN}Serial  : {info['serial']}")
    print(f"  {Fore.CYAN}Válido  : {info['not_before']} → {info['not_after']}")
    print(f"  {days_c}Expira  : {days} días{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Key     : {info['key_size']} bits  Alg: {info['sig_alg'].upper()}")
    print(f"  {Fore.CYAN}CA      : {info['is_ca']}")
    if info.get("sans"):
        print(f"  {Fore.CYAN}SANs    : {info['sans']}")
    if info["issues"]:
        print(f"\n  {Fore.YELLOW}Issues:{Style.RESET_ALL}")
        for level, msg in info["issues"]:
            c = Fore.RED if level in ("CRÍTICO","ALTO") else Fore.YELLOW
            print(f"    {c}[{level}]{Style.RESET_ALL} {msg}")
    else:
        print(f"  {Fore.GREEN}✓ Sin issues detectados{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="PKI Certificate Manager")
    sub = parser.add_subparsers(dest="cmd")

    ca_p = sub.add_parser("ca",     help="Generar Certificate Authority")
    ca_p.add_argument("--cn",       default="MyRootCA")
    ca_p.add_argument("--days",     type=int, default=3650)
    ca_p.add_argument("--bits",     type=int, default=4096)
    ca_p.add_argument("--out",      default="pki/ca")

    srv_p = sub.add_parser("server", help="Generar certificado de servidor")
    srv_p.add_argument("--cn",      required=True)
    srv_p.add_argument("--ca-key",  required=True)
    srv_p.add_argument("--ca-cert", required=True)
    srv_p.add_argument("--days",    type=int, default=365)
    srv_p.add_argument("--bits",    type=int, default=2048)
    srv_p.add_argument("--out",     default="pki/server")
    srv_p.add_argument("--sans",    nargs="+", default=[])

    ins_p = sub.add_parser("inspect", help="Inspeccionar certificado")
    ins_p.add_argument("cert")
    ins_p.add_argument("-o","--output", default=None)

    args = parser.parse_args()

    if args.cmd == "ca":
        generate_ca(args.cn, args.days, args.bits, args.out)

    elif args.cmd == "server":
        with open(args.ca_key,"rb") as f:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            ca_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(args.ca_cert,"rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        generate_server_cert(args.cn, ca_key, ca_cert, args.days, args.bits, args.out, args.sans)

    elif args.cmd == "inspect":
        info = inspect_cert(args.cert)
        print_cert_info(info)
        if args.output:
            with open(args.output,"w") as f:
                json.dump(info, f, indent=2, default=str)

    else:
        print("  Comandos: ca, server, inspect")
        print("  Ejemplo: python3 03_pki_manager.py ca --cn 'Mi CA'")
        print("  Ejemplo: python3 03_pki_manager.py inspect cert.pem")

if __name__ == "__main__":
    main()
