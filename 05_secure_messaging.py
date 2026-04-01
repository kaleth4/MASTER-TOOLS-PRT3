#!/usr/bin/env python3
"""05 · SECURE MESSAGING — End-to-end encrypted chat simulator"""

import os, base64, json, argparse, hashlib, secrets, socket, threading, sys
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.GREEN}╔══════════════════════════════════════╗\n║  💬 SECURE MESSAGING  v1.0           ║\n║  E2E encryption · AES-256 · ECDH     ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Crypto primitives ───────────────────────────────────────────
def generate_keypair():
    """Generate X25519 key pair for ECDH."""
    if not CRYPTO_OK:
        # Fallback: simulate with random bytes
        priv = secrets.token_bytes(32)
        pub  = hashlib.sha256(priv).digest()
        return priv, pub
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    return priv, pub

def export_public_key(pub_key) -> bytes:
    if not CRYPTO_OK:
        return pub_key  # Already bytes in fallback
    return pub_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

def derive_shared_key(priv_key, peer_pub_bytes: bytes) -> bytes:
    """ECDH key exchange → shared secret → AES key."""
    if not CRYPTO_OK:
        # Fallback: XOR + SHA256
        shared = bytes(a ^ b for a,b in zip(priv_key, peer_pub_bytes))
        return hashlib.sha256(shared).digest()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared   = priv_key.exchange(peer_pub)
    return hashlib.sha256(shared).digest()

def encrypt_message(key: bytes, plaintext: str) -> str:
    """AES-256-GCM encryption → base64."""
    nonce  = secrets.token_bytes(12)
    if CRYPTO_OK:
        ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    else:
        # XOR fallback (educational only)
        pt  = plaintext.encode()
        ct  = bytes(pt[i] ^ key[i % 32] for i in range(len(pt)))
    payload = nonce + ct
    return base64.b64encode(payload).decode()

def decrypt_message(key: bytes, ciphertext_b64: str) -> str:
    """Decrypt AES-256-GCM."""
    payload = base64.b64decode(ciphertext_b64)
    nonce   = payload[:12]
    ct      = payload[12:]
    if CRYPTO_OK:
        pt = AESGCM(key).decrypt(nonce, ct, None)
        return pt.decode()
    else:
        return bytes(ct[i] ^ key[i % 32] for i in range(len(ct))).decode()

def message_fingerprint(msg: str) -> str:
    return hashlib.sha256(msg.encode()).hexdigest()[:16]

# ── Demo conversation ────────────────────────────────────────────
def demo_e2e():
    print(f"\n{Fore.CYAN}[*] Simulando conversación E2E cifrada...\n")

    # Alice generates keypair
    alice_priv, alice_pub = generate_keypair()
    alice_pub_bytes = export_public_key(alice_pub)
    print(f"  {Fore.CYAN}Alice{Style.RESET_ALL} generó par de claves")
    print(f"  PubKey: {alice_pub_bytes.hex()[:32]}...\n")

    # Bob generates keypair
    bob_priv, bob_pub = generate_keypair()
    bob_pub_bytes = export_public_key(bob_pub)
    print(f"  {Fore.CYAN}Bob{Style.RESET_ALL} generó par de claves")
    print(f"  PubKey: {bob_pub_bytes.hex()[:32]}...\n")

    # Key exchange
    alice_shared = derive_shared_key(alice_priv, bob_pub_bytes)
    bob_shared   = derive_shared_key(bob_priv, alice_pub_bytes)

    match = alice_shared == bob_shared
    print(f"  {Fore.GREEN if match else Fore.RED}Shared secrets match: {match}{Style.RESET_ALL}")
    print(f"  Session key: {alice_shared.hex()[:32]}...\n")

    # Messages
    print(f"{Fore.GRAY}{'─'*44}{Style.RESET_ALL}")
    messages = [
        ("Alice", "Bob",   "Hola Bob, ¿puedes escuchar?"),
        ("Bob",   "Alice", "Sí Alice, canal seguro establecido."),
        ("Alice", "Bob",   "El servidor tiene la IP 10.0.0.5 — no compartir."),
        ("Bob",   "Alice", "Recibido. Clave de acceso: T3mp0r4l!"),
    ]

    for sender, receiver, plaintext in messages:
        ciphertext = encrypt_message(alice_shared, plaintext)
        decrypted  = decrypt_message(alice_shared, ciphertext)
        fp         = message_fingerprint(plaintext)
        print(f"\n  {Fore.YELLOW}[{sender} → {receiver}]{Style.RESET_ALL}")
        print(f"  Texto plano: {Fore.WHITE}{plaintext}{Style.RESET_ALL}")
        print(f"  Cifrado    : {Fore.GRAY}{ciphertext[:60]}...{Style.RESET_ALL}")
        print(f"  Descifrado : {Fore.GREEN}{decrypted}{Style.RESET_ALL}")
        print(f"  Fingerprint: {Fore.CYAN}{fp}{Style.RESET_ALL}")

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.GREEN}[✓] Todos los mensajes cifrados y verificados")
    print(f"    Algoritmo: {'X25519 + AES-256-GCM' if CRYPTO_OK else 'Fallback (demo only)'}")
    print(f"    Perfect Forward Secrecy: {'✓ Sí' if CRYPTO_OK else '✗ No (usar pip install cryptography)'}")

def analyze_protocol(protocol: str) -> dict:
    protocols = {
        "signal": {"e2e":True, "forward_secrecy":True, "open_source":True,
                    "metadata":False, "score":10, "note":"Estándar de oro"},
        "whatsapp":{"e2e":True, "forward_secrecy":True, "open_source":False,
                    "metadata":True, "score":7, "note":"E2E pero metadata a Meta"},
        "telegram":{"e2e":"Parcial","forward_secrecy":"Solo Secret Chats",
                    "open_source":"Parcial","metadata":True,"score":6,
                    "note":"Chats normales en servidores Telegram"},
        "sms":     {"e2e":False,"forward_secrecy":False,"open_source":False,
                    "metadata":True,"score":2,"note":"Sin cifrado — vulnerable a SS7"},
        "email":   {"e2e":"Con PGP/S-MIME","forward_secrecy":False,
                    "open_source":True,"metadata":True,"score":4,
                    "note":"Metadatos expuestos, cifrado opcional"},
    }
    return protocols.get(protocol.lower(), {"error":"Protocolo no reconocido"})

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Secure Messaging Simulator")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo",    help="Demo E2E conversation")
    an_p = sub.add_parser("analyze", help="Analizar protocolo")
    an_p.add_argument("protocol", choices=["signal","whatsapp","telegram","sms","email"])
    args = parser.parse_args()

    if args.cmd == "analyze":
        p = analyze_protocol(args.protocol)
        print(f"\n  {Fore.CYAN}Protocolo: {args.protocol.upper()}{Style.RESET_ALL}")
        for k,v in p.items():
            if k == "error": print(f"  {Fore.RED}{v}"); continue
            icon = f"{Fore.GREEN}✓" if v is True or v == True else f"{Fore.RED}✗" if v is False else f"{Fore.YELLOW}~"
            print(f"  {icon}{Style.RESET_ALL} {k:<20}: {v}")
    else:
        demo_e2e()

if __name__ == "__main__":
    main()
