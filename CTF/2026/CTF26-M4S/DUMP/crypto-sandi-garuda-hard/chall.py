#!/usr/bin/env python3
import os, hashlib
from Crypto.Cipher import AES

# secp256k1
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv(a, m): return pow(a, -1, m)
def ec_add(A, B):
    if A is None: return B
    if B is None: return A
    x1, y1 = A; x2, y2 = B
    if x1 == x2 and (y1 + y2) % P == 0: return None
    m = (3*x1*x1)*inv(2*y1, P) % P if A == B else (y2-y1)*inv((x2-x1) % P, P) % P
    x3 = (m*m - x1 - x2) % P
    return (x3, (m*(x1-x3) - y1) % P)
def ec_mul(k, Pt):
    R = None
    while k:
        if k & 1: R = ec_add(R, Pt)
        Pt = ec_add(Pt, Pt); k >>= 1
    return R

G = (Gx, Gy)
def H(msg): return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

MESSAGES = [
    b"NOTA-DINAS/2026: distribusi kunci sesi antar-kementerian",
    b"NOTA-DINAS/2026: rotasi sertifikat gerbang identitas nasional",
    b"NOTA-DINAS/2026: pengesahan manifest firmware HSM Garuda",
    b"NOTA-DINAS/2026: audit berkala modul tanda tangan pusat",
    b"NOTA-DINAS/2026: sinkronisasi waktu tepercaya wilayah barat",
    b"NOTA-DINAS/2026: pencabutan token layanan pihak ketiga",
]

def main():
    flag = open("flag.txt", "rb").read().strip()
    d = int.from_bytes(os.urandom(32), "big") % N
    Q = ec_mul(d, G)
    c = int.from_bytes(os.urandom(32), "big") % N
    k = int.from_bytes(os.urandom(32), "big") % N
    if k == 0: k = 1

    sigs = []
    for msg in MESSAGES:
        while True:
            R = ec_mul(k, G); r = R[0] % N; z = H(msg)
            if r != 0:
                s = (inv(k, N) * (z + r * d)) % N
                if s != 0: break
            k = (k * k + c) % N
        sigs.append((msg, r, s))
        k = (k * k + c) % N

    key = hashlib.sha256(b"garuda-hsm-key||" + d.to_bytes(32, "big")).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=b"garuda-iv-01")
    ct, tag = cipher.encrypt_and_digest(flag)

    with open("output.txt", "w") as f:
        f.write("curve = secp256k1\n")
        f.write(f"n  = {N}\n")
        f.write(f"Qx = {Q[0]}\n")
        f.write(f"Qy = {Q[1]}\n")
        f.write("signatures = [\n")
        for msg, r, s in sigs:
            f.write(f"    ({msg!r}, {r}, {s}),\n")
        f.write("]\n")
        f.write(f"flag_nonce = {b'garuda-iv-01'.hex()}\n")
        f.write(f"flag_ct    = {ct.hex()}\n")
        f.write(f"flag_tag   = {tag.hex()}\n")

if __name__ == "__main__":
    main()
