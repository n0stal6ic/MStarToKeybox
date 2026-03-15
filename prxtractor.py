import re
import sys
import os
from Crypto.Cipher import AES
from hashlib import md5

def strings_dump(filepath, min_len=6):
    with open(filepath, "rb") as f:
        data = f.read()
    pattern = rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}'
    return data, [m.group().decode("ascii") for m in re.finditer(pattern, data)]

def find_playready_phrases(filepath):
    data, hits = strings_dump(filepath, min_len=6)

    known_hints = ["pszBasePhrase", "pszAdditionalPhrase", "pszPhrase", "Salted__"]
    print("[*] Known marker strings found:")
    for h in hits:
        if any(hint.lower() in h.lower() for hint in known_hints):
            print(f"  [hint] {h}")

    print("\n[*] Potential base+additional passphrase pairs:")
    passphrase = None
    concat_pattern = rb'([\x20-\x7E]{6,24})\x00+([\x20-\x7E]{6,24})'
    for m in re.finditer(concat_pattern, data):
        a, b = m.group(1).decode(), m.group(2).decode()
        if re.match(r'^[A-Za-z0-9]{6,24}$', a) and re.match(r'^[A-Za-z0-9]{6,24}$', b):
            if not passphrase:
                passphrase = a + b
            print(f"  '{a}' + '{b}' => '{a+b}'")
    if not passphrase:
        print("  None found.")
    
    return passphrase

def openssl_kdf(passphrase: str, salt: bytes):
    data = passphrase.encode()
    d, d_i = b"", b""
    while len(d) < 48:
        d_i = md5(d_i + data + salt).digest()
        d += d_i
    return d[:32], d[32:48]

def decrypt_dat(dat_path: str, passphrase: str, strip_padding: bool = False):
    with open(dat_path, "rb") as f:
        raw = f.read()

    if raw[:8] != b"Salted__":
        print(f"  [!] {dat_path} does not have OpenSSL Salted__ header — skipping")
        return None

    salt = raw[8:16]
    ciphertext = raw[16:]

    key, iv = openssl_kdf(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    if strip_padding:
        decrypted = decrypted[:-8]
        print(f"  [*] Stripped last 8 bytes (zgpriv padding)")

    pad_len = decrypted[-1]
    if 1 <= pad_len <= 16:
        decrypted = decrypted[:-pad_len]

    out_path = dat_path.replace(".dat", "_decrypted.bin")
    with open(out_path, "wb") as f:
        f.write(decrypted)
    print(f"  [+] Decrypted -> {out_path} ({len(decrypted)} bytes)")
    return out_path

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: prxtractor.py <libplayready.so.0> [bgroupcert.dat] [zgpriv.dat]")
        sys.exit(1)

    so_path = sys.argv[1]
    bgroupcert_path = sys.argv[2] if len(sys.argv) > 2 else None
    zgpriv_path = sys.argv[3] if len(sys.argv) > 3 else None

    print(f"[*] Scanning {so_path}...\n")
    passphrase = find_playready_phrases(so_path)

    if passphrase and bgroupcert_path:
        print(f"\n[*] Decrypting {bgroupcert_path}...")
        decrypt_dat(bgroupcert_path, passphrase, strip_padding=False)

    if passphrase and zgpriv_path:
        print(f"\n[*] Decrypting {zgpriv_path}...")
        decrypt_dat(zgpriv_path, passphrase, strip_padding=True)