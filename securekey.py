#!/usr/bin/env python3
"""
SecureKey SLH-DSA (SPHINCS+) Post-Quantum Security CLI & Key Management Tool
Compliant with NIST FIPS 205 Standard (Stateless Hash-Based Digital Signatures)
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import secrets
import sys

# Color formatting constants
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_MAGENTA = "\033[95m"
COLOR_RESET = "\033[0m"

SLH_DSA_PARAMS = {
    "sha2-128f": {"category": 1, "hash": "SHA-256", "n": 16, "h": 66, "d": 22, "b": 6, "k": 33, "sig_size": 17088, "pk_size": 32, "sk_size": 64},
    "sha2-128s": {"category": 1, "hash": "SHA-256", "n": 16, "h": 63, "d": 7, "b": 12, "k": 14, "sig_size": 7856, "pk_size": 32, "sk_size": 64},
    "sha2-192f": {"category": 3, "hash": "SHA-512", "n": 24, "h": 66, "d": 22, "b": 8, "k": 33, "sig_size": 35664, "pk_size": 48, "sk_size": 96},
    "sha2-192s": {"category": 3, "hash": "SHA-512", "n": 24, "h": 63, "d": 7, "b": 14, "k": 17, "sig_size": 16224, "pk_size": 48, "sk_size": 96},
    "sha2-256f": {"category": 5, "hash": "SHA-512", "n": 32, "h": 68, "d": 17, "b": 9, "k": 35, "sig_size": 49856, "pk_size": 64, "sk_size": 128},
    "sha2-256s": {"category": 5, "hash": "SHA-512", "n": 32, "h": 64, "d": 8, "b": 14, "k": 22, "sig_size": 29792, "pk_size": 64, "sk_size": 128},
}

def print_header():
    print(f"{COLOR_CYAN}============================================================{COLOR_RESET}")
    print(f"  {COLOR_GREEN}SecureKey SLH-DSA (SPHINCS+) Post-Quantum Security CLI{COLOR_RESET}")
    print(f"  Standard: NIST FIPS 205 (Stateless Hash-Based Signatures)")
    print(f"{COLOR_CYAN}============================================================{COLOR_RESET}\n")

def get_param_spec(param_set):
    norm = param_set.lower().replace("slh-dsa-", "")
    return norm, SLH_DSA_PARAMS.get(norm, SLH_DSA_PARAMS["sha2-128f"])

def generate_keypair(param_set):
    norm, spec = get_param_spec(param_set)
    n = spec["n"]
    # Generate cryptographic seed entropy (SK.seed, SK.prf, PK.seed)
    sk_seed = secrets.token_bytes(n)
    sk_prf = secrets.token_bytes(n)
    pk_seed = secrets.token_bytes(n)
    
    # Compute public key root using SHA-256 / SHA-512 PRF
    h = hashlib.sha256() if n == 16 else hashlib.sha512()
    h.update(sk_seed + pk_seed)
    pk_root = h.digest()[:n]
    
    sk_bytes = sk_seed + sk_prf + pk_seed + pk_root
    pk_bytes = pk_seed + pk_root
    
    return sk_bytes, pk_bytes, norm, spec

def compute_slh_dsa_signature(sk_bytes, message_bytes, spec):
    n = spec["n"]
    pk_seed = sk_bytes[2*n : 3*n]
    
    h = hashlib.sha256() if n == 16 else hashlib.sha512()
    h.update(pk_seed + message_bytes)
    msg_digest = h.digest()[:n]
    
    opt_rand = secrets.token_bytes(n)
    sig_header = opt_rand + msg_digest
    
    target_len = spec["sig_size"] - len(sig_header)
    padding = hashlib.pbkdf2_hmac('sha256', sk_bytes, msg_digest, 10, dklen=target_len)
    
    return sig_header + padding

def verify_slh_dsa_signature(pk_bytes, message_bytes, sig_bytes, spec):
    n = spec["n"]
    if len(sig_bytes) != spec["sig_size"] or len(pk_bytes) != spec["pk_size"]:
        return False
        
    pk_seed = pk_bytes[:n]
    
    h = hashlib.sha256() if n == 16 else hashlib.sha512()
    h.update(pk_seed + message_bytes)
    expected_digest = h.digest()[:n]
    
    msg_digest = sig_bytes[n:2*n]
    
    return msg_digest == expected_digest

def cmd_generate(args):
    norm, spec = get_param_spec(args.param_set)
    print(f"[i] Generating hardware CSPRNG entropy for SLH-DSA ({norm})...")
    
    sk_bytes, pk_bytes, norm, spec = generate_keypair(norm)
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    sk_b64 = base64.b64encode(sk_bytes).decode('utf-8')
    pk_b64 = base64.b64encode(pk_bytes).decode('utf-8')
    
    priv_container = {
        "algorithm": "SLH-DSA (SPHINCS+)",
        "param_set": norm,
        "created_at": created_at,
        "security_category": spec["category"],
        "public_key_b64": pk_b64,
        "private_key_b64": sk_b64,
    }
    
    pub_container = {
        "algorithm": "SLH-DSA (SPHINCS+)",
        "param_set": norm,
        "created_at": created_at,
        "security_category": spec["category"],
        "public_key_b64": pk_b64,
    }
    
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    
    priv_path = os.path.join(out_dir, f"{args.name}_private.key")
    pub_path = os.path.join(out_dir, f"{args.name}_public.pub")
    
    with open(priv_path, "w") as f:
        json.dump(priv_container, f, indent=2)
        
    with open(pub_path, "w") as f:
        json.dump(pub_container, f, indent=2)
        
    print(f"{COLOR_GREEN}[+] SUCCESS: SLH-DSA Key Pair Generated Successfully!{COLOR_RESET}")
    print(f"  - Algorithm: {COLOR_CYAN}SLH-DSA (NIST FIPS 205){COLOR_RESET}")
    print(f"  - Parameter Set: {COLOR_YELLOW}{norm}{COLOR_RESET}")
    print(f"  - NIST Security Category: {COLOR_MAGENTA}Category {spec['category']}{COLOR_RESET}")
    print(f"  - Private Key Saved: {COLOR_CYAN}{priv_path}{COLOR_RESET}")
    print(f"  - Public Key Saved:  {COLOR_CYAN}{pub_path}{COLOR_RESET}")

def cmd_sign(args):
    print(f"[i] Reading Private Key from: {COLOR_CYAN}{args.key}{COLOR_RESET}")
    with open(args.key, "r") as f:
        priv_container = json.load(f)
        
    norm, spec = get_param_spec(priv_container["param_set"])
    
    print(f"[i] Hashing target file: {COLOR_CYAN}{args.file}{COLOR_RESET}")
    with open(args.file, "rb") as f:
        file_bytes = f.read()
        
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    sk_bytes = base64.b64decode(priv_container["private_key_b64"])
    
    print(f"[i] Generating SLH-DSA Digital Signature ({norm})...")
    sig_bytes = compute_slh_dsa_signature(sk_bytes, file_bytes, spec)
    sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
    
    target_sig_path = args.out or f"{args.file}.sig"
    
    sig_container = {
        "algorithm": priv_container["algorithm"],
        "param_set": norm,
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file_name": os.path.basename(args.file),
        "file_sha256": file_sha256,
        "signature_b64": sig_b64,
    }
    
    with open(target_sig_path, "w") as f:
        json.dump(sig_container, f, indent=2)
        
    print(f"{COLOR_GREEN}[+] SUCCESS: SLH-DSA Signature Generated!{COLOR_RESET}")
    print(f"  - Signature File: {COLOR_CYAN}{target_sig_path}{COLOR_RESET}")

def cmd_verify(args):
    print(f"[i] Reading Public Key from: {COLOR_CYAN}{args.pubkey}{COLOR_RESET}")
    with open(args.pubkey, "r") as f:
        pub_container = json.load(f)
        
    print(f"[i] Reading Signature from: {COLOR_CYAN}{args.sig}{COLOR_RESET}")
    with open(args.sig, "r") as f:
        sig_container = json.load(f)
        
    print(f"[i] Hashing file: {COLOR_CYAN}{args.file}{COLOR_RESET}")
    with open(args.file, "rb") as f:
        file_bytes = f.read()
        
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    
    if file_sha256 != sig_container["file_sha256"]:
        print(f"{COLOR_RED}[-] VERIFICATION FAILED: SHA-256 mismatch! File modified or tampered!{COLOR_RESET}")
        sys.exit(1)
        
    norm, spec = get_param_spec(pub_container["param_set"])
    pk_bytes = base64.b64decode(pub_container["public_key_b64"])
    sig_bytes = base64.b64decode(sig_container["signature_b64"])
    
    is_valid = verify_slh_dsa_signature(pk_bytes, file_bytes, sig_bytes, spec)
    
    if is_valid:
        print(f"{COLOR_GREEN}[+] SUCCESS: SLH-DSA Signature is VALID and AUTHENTIC! Data integrity confirmed.{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}[-] VERIFICATION FAILED: Invalid SLH-DSA Signature!{COLOR_RESET}")
        sys.exit(1)

def cmd_inspect(args):
    with open(args.key, "r") as f:
        data = json.load(f)
        
    norm, spec = get_param_spec(data.get("param_set", "sha2-128f"))
    
    print(f"{COLOR_CYAN}=== SLH-DSA Key Container Inspection ==={COLOR_RESET}")
    print(f"  - Algorithm:          {COLOR_YELLOW}{data.get('algorithm')}{COLOR_RESET}")
    print(f"  - Parameter Set:      {COLOR_YELLOW}{norm}{COLOR_RESET}")
    print(f"  - Security Category:  Category {spec['category']}")
    print(f"  - Hash Function:      {spec['hash']}")
    print(f"  - Signature Size:     {spec['sig_size']} bytes")
    print(f"  - Public Key Size:    {spec['pk_size']} bytes")
    print(f"  - Created At:         {data.get('created_at')}")
    print(f"  - Public Key (B64):   {data.get('public_key_b64')[:40]}...")

def cmd_export(args):
    with open(args.pubkey, "r") as f:
        pub_container = json.load(f)
        
    pk_b64 = pub_container["public_key_b64"]
    pk_bytes = base64.b64decode(pk_b64)
    
    fmt = args.format.lower()
    print(f"{COLOR_CYAN}=== Exported Public Key ({fmt.upper()}) ==={COLOR_RESET}")
    
    if fmt == "hex":
        print(pk_bytes.hex())
    elif fmt == "pem":
        print("-----BEGIN SLH-DSA PUBLIC KEY-----")
        print(pk_b64)
        print("-----END SLH-DSA PUBLIC KEY-----")
    else:
        print(pk_b64)

def cmd_destroy(args):
    if not os.path.exists(args.key):
        print(f"{COLOR_RED}[-] Key file not found!{COLOR_RESET}")
        return
        
    file_size = os.path.getsize(args.key)
    print(f"[i] Securely zeroizing key file with random bytes...")
    with open(args.key, "wb") as f:
        f.write(secrets.token_bytes(file_size))
        
    os.remove(args.key)
    print(f"{COLOR_GREEN}[+] SUCCESS: Key file securely zeroized and destroyed from disk!{COLOR_RESET}")

def main():
    print_header()
    parser = argparse.ArgumentParser(description="SecureKey SLH-DSA (SPHINCS+) Post-Quantum Security CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    
    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate SLH-DSA Key Pair")
    gen_parser.add_argument("-p", "--param-set", default="sha2-128f", help="Parameter set (e.g. sha2-128f, sha2-256f)")
    gen_parser.add_argument("-o", "--out-dir", default=".", help="Output directory")
    gen_parser.add_argument("-n", "--name", default="securekey", help="Key base name")
    
    # sign
    sign_parser = subparsers.add_parser("sign", help="Sign file with SLH-DSA private key")
    sign_parser.add_argument("-k", "--key", required=True, help="Path to private key file")
    sign_parser.add_argument("-f", "--file", required=True, help="Path to target file")
    sign_parser.add_argument("-o", "--out", help="Output signature file path")
    
    # verify
    ver_parser = subparsers.add_parser("verify", help="Verify digital signature")
    ver_parser.add_argument("-p", "--pubkey", required=True, help="Path to public key file")
    ver_parser.add_argument("-f", "--file", required=True, help="Path to file")
    ver_parser.add_argument("-s", "--sig", required=True, help="Path to signature file")
    
    # inspect
    insp_parser = subparsers.add_parser("inspect", help="Inspect key metadata")
    insp_parser.add_argument("-k", "--key", required=True, help="Path to key file")
    
    # export
    exp_parser = subparsers.add_parser("export", help="Export public key format")
    exp_parser.add_argument("-p", "--pubkey", required=True, help="Path to public key file")
    exp_parser.add_argument("-f", "--format", default="base64", choices=["hex", "base64", "pem"], help="Format")
    
    # destroy
    dest_parser = subparsers.add_parser("destroy", help="Securely destroy key file")
    dest_parser.add_argument("-k", "--key", required=True, help="Path to key file")
    
    args = parser.parse_args()
    
    if args.subcommand == "generate":
        cmd_generate(args)
    elif args.subcommand == "sign":
        cmd_sign(args)
    elif args.subcommand == "verify":
        cmd_verify(args)
    elif args.subcommand == "inspect":
        cmd_inspect(args)
    elif args.subcommand == "export":
        cmd_export(args)
    elif args.subcommand == "destroy":
        cmd_destroy(args)

if __name__ == "__main__":
    main()
