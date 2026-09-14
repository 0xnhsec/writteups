# taptap — Crypto Writeup

> Kategori: Crypto  
> Tanggal: 2026-09-13  
> Scope: [case scope](work/taptap/scope.md)  
> Flag: `pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}`

## Ringkasan

Challenge memberikan 180 nilai high bits dari sebuah linear recurrence berorde 25. Modulus prima dan seluruh koefisien recurrence dirahasiakan, tetapi modulus berada sangat dekat dengan `2^128`. Karena hanya 48 low bits yang hilang, data tersebut dapat dipulihkan dengan lattice attack untuk truncated Fibonacci LFSR dengan modulus tidak diketahui.

Setelah modulus dan characteristic polynomial ditemukan, Kannan embedding memulihkan low bits dari sebagian output. Sequence kemudian di-rewind untuk mendapatkan state awal, lalu seluruh sequence dipakai untuk membentuk key SHAKE-256 dan mendekripsi ciphertext.

## Evidence → Finding → Path

### Evidence

| ID | Observasi | Sumber |
|---|---|---|
| E-001 | Source membuat `p` sebagai prima `2^128 - Δ`, dengan `Δ` 48–50 bit, lalu membangkitkan recurrence orde 25. | `chall.py` |
| E-002 | Output yang diberikan adalah `ai >> 48`; tersedia 180 output dan ciphertext berukuran 73 byte. | `chall.py` |
| E-003 | Unknown-modulus lattice menghasilkan annihilating polynomials; gcd 12 resultant berukuran 3200 bit. | Eksekusi solver lokal |
| E-004 | Akar pangkat 25 dari gcd resultant menghasilkan `p = 340282366920938463463374127620052448857`. | Eksekusi solver lokal |
| E-005 | Kannan lattice memulihkan 64 full outputs dan semuanya memenuhi recurrence modulo `p`; high bits seluruh 180 output cocok. | Verifikasi solver lokal |
| E-006 | SHAKE-256 XOR ciphertext menghasilkan flag yang valid dengan format `pwnsec{...}`. | Dekripsi lokal |

### Finding

`F-001` — **Truncated linear recurrence dapat dipulihkan** (`reverse_algo`, validated).  
Evidence: E-001 sampai E-005. Karena recurrence linear, output yang dipotong tetap memuat cukup banyak hubungan modular untuk memulihkan modulus, koefisien, dan state.

### Solve path

`P-001` — `chall.py` → high-bit sequence → unknown-modulus lattice → resultant gcd → modulus → characteristic polynomial → Kannan embedding → rewind → SHAKE-256 → flag.

```mermaid
flowchart LR
    source["chall.py"] --> trunc["180 high-bit outputs"]
    trunc --> lattice["Unknown-modulus lattice"]
    lattice --> resultants["Annihilating polynomials + resultants"]
    resultants --> modulus["Recover p"]
    modulus --> recurrence["Recover characteristic polynomial"]
    recurrence --> lowbits["Kannan embedding: recover low bits"]
    lowbits --> rewind["Rewind 25 steps to initial state"]
    rewind --> key["SHA-256 + SHAKE-256"]
    key --> flag["Decrypt flag"]
```

## Analisis source

Source membangkitkan modulus dan data sebagai berikut:

```python
p = 2**128 - randint(2**48, 2**50)
while not isPrime(p):
    p -= 1

n = 25
C = [randint(1, p) for _ in range(n)]
A = [randint(1, p) for _ in range(n)]

for _ in range(180):
    A.append(
        sum(ci * ai for ci, ai in zip(C[::-1], A[::-1])) % p
    )

Y = [ai >> 48 for ai in A[::-1][:180]][::-1]
```

Jika sequence ditulis secara kronologis, recurrence tersebut sama dengan:

\[
a_{i+25} = \sum_{j=0}^{24} c_j a_{i+j} \pmod p.
\]

Karena yang diketahui hanya high bits, setiap nilai dapat ditulis sebagai:

\[
a_i = 2^{48}y_i + z_i,
\qquad 0 \leq z_i < 2^{48}.
\]

Jadi terdapat 80 bit yang diketahui dan 48 bit tersembunyi pada setiap output.

## 1. Unknown-modulus lattice

Untuk mencari polynomial yang menganihilasi sequence, dibangun lattice dengan parameter:

- order recurrence `n = 25`;
- public bits `h = 80`;
- `r = t = 90`, sehingga dimensi lattice adalah `180`;
- jumlah output minimum `r + t - 1 = 179`, sedangkan challenge memberikan 180 output.

Bentuk basis yang dipakai adalah:

\[
B =
\begin{pmatrix}
2^{80}I_t & 0 \\
H & I_r
\end{pmatrix},
\qquad H_{i,j}=y_{i+j}.
\]

Setelah basis direduksi dengan `flatter`, tail dari short vectors dibaca sebagai koefisien polynomial. Polynomial-polynomial ini bukan characteristic polynomial langsung, tetapi semuanya memiliki characteristic polynomial sequence sebagai faktor modulo `p`.

## 2. Recover modulus dengan resultant

Untuk dua annihilating polynomials `F` dan `G`, characteristic polynomial yang sama menyebabkan resultant memenuhi:

\[
p^{25} \mid \operatorname{Res}(F,G).
\]

GCD dari beberapa resultant mengandung `p^25`. Pada instance ini:

```text
gcd(resultants): 3200 bits
25th root:       340282366920938463463374127620052448857
```

Modulus yang ditemukan adalah:

```text
p = 340282366920938463463374127620052448857
Δ = 2^128 - p = 479811715762599
```

Nilai `Δ` berada pada range yang dijanjikan source.

## 3. Recover recurrence coefficients

Semua candidate polynomial direduksi modulo `p`, kemudian dihitung gcd polynomial pada `GF(p)`.

GCD tersebut menghasilkan monic characteristic polynomial berorde 25:

\[
f(x)=x^{25}-c_{24}x^{24}-\cdots-c_1x-c_0.
\]

Koefisien recurrence diperoleh dari:

\[
c_i = -[x^i]f(x) \pmod p.
\]

## 4. Recover low bits

Dengan `p` dan koefisien sudah diketahui, sequence dapat diekspresikan sebagai kombinasi linear dari 25 nilai awal. Kannan embedding kemudian digunakan untuk mencari vector yang memuat nilai low bits yang telah digeser ke pusat interval.

Untuk efisiensi, 64 dari 180 output digunakan pada tahap ini. Lattice yang dibangun memiliki dimensi `65` (`d + 1`). Candidate vector diverifikasi dengan dua syarat:

1. setiap low bit berada pada interval `[0, 2^48)`;
2. seluruh nilai memenuhi recurrence modulo `p`.

Verifikasi berhasil dan full outputs yang ditemukan konsisten dengan semua high bits yang diberikan.

## 5. Rewind state dan dekripsi

Output pertama adalah `A[25]`, sehingga sequence di-rewind sebanyak 25 langkah menggunakan:

\[
a_i = c_0^{-1}\left(a_{i+25}-\sum_{j=1}^{24}c_j a_{i+j}\right) \pmod p.
\]

Dari state awal, seluruh 205 nilai `A` dibangkitkan ulang. Key dibuat oleh source dengan:

```python
seed = sha256(''.join(map(str, A)).encode()).digest()
key = shake_256(seed).digest(len(flag))
ct = strxor(key, flag)
```

Maka plaintext didapatkan dengan `ct XOR SHAKE-256(seed)`.

## Solver core

Contoh inti solve menggunakan toolkit Sage/Python untuk truncated Fibonacci LFSR:

```python
import ast
import hashlib
import re
from pathlib import Path

from scripts.lsb_truncated_fibonacci_lfsr_solver import (
    generate_sequence,
    solve_auto_from_outputs,
)

text = Path("chall.py").read_text()
ys = ast.literal_eval(re.findall(r"(?m)^\[(\d[^\n]*)\]$", text)[0])
ct = bytes.fromhex(re.findall(r"(?m)^([0-9a-f]{146})$", text)[0])

result = solve_auto_from_outputs(
    n=25,
    k=128,
    h=80,
    ell=48,
    outputs=ys,
    r=90,
    t=90,
    near_power=128,
    near_side="below",
    modulus_offset_bits=50,
    start_index=25,
    d=64,
    reduction="flatter",
    verbose=True,
)

p = result["modulus"]
coeffs = result["feedback_coefficients"]
initial = result["initial_state"]
A = generate_sequence(initial, coeffs, p, 205)

assert [a >> 48 for a in A[25:]] == ys

seed = hashlib.sha256("".join(map(str, A)).encode()).digest()
key = hashlib.shake_256(seed).digest(len(ct))
flag = bytes(x ^ y for x, y in zip(key, ct))
print(flag.decode())
```

Catatan: toolkit memerlukan SageMath dan executable `flatter`. Untuk instance ini, `r=t=90` cukup karena 180 output tersedia dan lattice unknown-modulus berukuran 180×180.

## Flag

```text
pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}
```

## Knowledge points

- Truncated-output attack pada linear recurrence.
- Unknown-modulus lattice.
- Annihilating polynomial dan resultant.
- Recover modulus dari `gcd(resultants)`.
- Polynomial gcd pada finite field.
- Kannan embedding untuk memulihkan hidden low bits.
- Rewind linear recurrence.
- SHA-256 dan SHAKE-256 sebagai key derivation.
