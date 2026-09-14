#!/usr/bin/env python3
"""
GeprekChain - starter kit untuk peserta.

Script ini HANYA memuat & menampilkan rantai serta memvalidasi struktur dasar.
Sisanya... tugasmu. 🌶️  Isi bagian TODO untuk mendekripsi `data`.
"""
import hashlib
import json
import base64
import sys

DIFFICULTY = 4
PREFIX = "0" * DIFFICULTY


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def block_hash(b: dict) -> str:
    """Hash sebuah blok. Perhatikan: field `hash` TIDAK ikut di-hash."""
    header = json.dumps({
        "index":         b["index"],
        "timestamp":     b["timestamp"],
        "transactions":  b["transactions"],
        "data":          b["data"],
        "previous_hash": b["previous_hash"],
        "nonce":         b["nonce"],
    }, sort_keys=True, separators=(",", ":"))
    return sha256_hex(header)


def load_chain(path="chain.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(chain):
    ok = True
    for i, blk in enumerate(chain):
        h = block_hash(blk)
        if h != blk["hash"]:
            print(f"  [!] blok {i}: hash tidak cocok"); ok = False
        if not blk["hash"].startswith(PREFIX):
            print(f"  [!] blok {i}: PoW tidak valid"); ok = False
        if i > 0 and blk["previous_hash"] != chain[i - 1]["hash"]:
            print(f"  [!] blok {i}: previous_hash putus"); ok = False
    return ok


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "chain.json"
    chain = load_chain(path)
    print(f"[+] Memuat {len(chain)} blok dari {path}\n")

    for blk in chain:
        print(f"  #{blk['index']}  hash={blk['hash'][:16]}...  "
              f"data={blk['data']}")

    print("\n[+] Memvalidasi rantai...")
    print("[+] Valid!" if validate(chain) else "[!] Rantai bermasalah!")

    # ------------------------------------------------------------------
    # TODO(peserta): dekripsi field `data` tiap blok.
    #   Petunjuk: base64_decode(data) XOR bytes.fromhex(previous_hash)
    #   Lalu gabungkan fragmen sesuai urutan `index`.
    #   Ingat: genesis (index 0) itu jebakan. :)
    # ------------------------------------------------------------------


if __name__ == "__main__":
    main()
