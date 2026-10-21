# What each lab proves — and what it does not

## CVE-2026-109619 — stale global state

Lab: `php2shell.py 109619 --php 8.5.11|8.5.12`

What it does: two multipart POSTs to one PHP worker, both carrying a 32-byte
session ID in the `Cookie: PHPSESSID=` header (PHP's upload-progress handler
rejects short IDs, which is why the ID length matters). The first carries a
2,000,000-byte filename in the upload-progress field, which makes the session
encode run out of memory inside `php_hash_environment()`, before
`PHP_RINIT_FUNCTION(basic)`. `BG(serialize)` keeps `level=1` and a pointer to a
context that request shutdown frees. The second POST reuses that context and the
worker dies (SIGSEGV, exit 139 in the lab).

Proves: the stale-context reuse is real on 8.5.11 and gone on 8.5.12.

Does not prove: code execution. The reference PoC
([RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf))
stops at memory corruption, and so does this lab. Turning the corrupted
`HashTable` into a controlled write is a separate research step.

Instrumented evidence: a build with `fprintf` in `php_var_serialize_init()`
prints `SER_INIT level=0 data=(nil)` and `SER_ALLOC` for the arm request, and no
`SER_DESTROY` before the fatal — the context is left behind exactly as the
mechanism predicts. The instrumentation was only built for 8.5.11; the 8.5.12
side is behavioural (the worker survives).

The docroot is `/srv/php2shell-docroot` (22 characters). The reference PoC
measured a 22..29 window on Arch for the freed 64-byte block to be recycled by
the `SCRIPT_FILENAME` string; this repo did not re-measure that window on its
own build, so treat the length as part of the reproduction recipe, not as a
requirement derived here. `--control` and the fixed build are the controls.

SAPI note (`--sapi fpm`): php-fpm does **not** reproduce this path, for two
separate reasons, both measured:

- With the startup-OOM producer the arm request's fatal exits the child
  (`child N exited with code 70`) and the master respawns it, so the fire
  request lands on a fresh process.
- With an application-level producer (`produce.php`: `serialize()` of a 4 MB
  string under `memory_limit=8M`) the child survives and the instrumented build
  shows the intended stale state: `SER_INIT level=0` → `SER_ALLOC` →
  `SER_INIT level=1` → `SER_DESTROY level=2` (decrements to 1, no free) → fatal.
  But in the next request the upload-progress encode runs **after**
  `PHP_RINIT_FUNCTION(basic)` (`SER_RINIT_RESET` appears first, then
  `SER_INIT level=0 data=(nil)`), so RINIT has already cleared the context and
  the encode starts fresh. Under the cli-server the same encode runs before
  RINIT, which is why the cli lab fires.

So the BG(serialize) variant of 109619 is cli-server-shaped. The official FPM
session-lifecycle path must use other worker-retained state, not this context.

## CVE-2026-109618 — OOM corruption during request startup

Lab: `php2shell.py 109618 --php 8.5.11|8.5.12 --vector headers|nested|chunked`

What it does: sends multipart bodies whose in-memory representation is much
larger than their wire size, under `memory_limit=16M` and `post_max_size=32M`,
to mod_php. The advisory names three amplifiers: an unrestricted number of
headers per part, deeply nested field names, and bodies without a usable
`Content-Length`.

Proves: whatever the run reports — a crash marker on 8.5.11 and none on 8.5.12
means the startup-OOM path is reachable; an OOM without a crash means the
amplifier fired but the corruption did not manifest.

Measured on this build (2026-10-21, 16M/32M, `--vector headers` with 200,000
part headers): 8.5.11 returns 200 with
`Allowed memory size of 16777216 bytes exhausted (tried to allocate 4096 bytes)
in Unknown on line 0` — the startup OOM, before any script — and the worker
survives. 8.5.12 returns a normal 200 with no OOM at all. The `nested` and
`chunked` vectors returned 200 in our runs without adding a crash. So this lab
reproduces the **precondition** and shows the fixed build no longer reaches it;
it does not reproduce the corruption or an RCE.

Does not prove: a working RCE. The advisory describes the corruption as a
precondition for RCE, not as a public exploit.

ASAN attempt: mod_php 8.5.11 built with `-fsanitize=address`,
`USE_ZEND_ALLOC=0`, `USE_TRACKED_ALLOC=1` and a 64 MB custom-heap limit
(`templates/zend-alloc-limit.patch`, the instrumentation the audit describes).
The `headers` vector with 1,000,000 part headers reaches the startup OOM, but
ASAN reports nothing. The `emptyfiles` vector (300,000 empty file controls over
chunked transport) and the `chunked` vector (48 MB) do not reach the OOM in this
setup. The corruption is therefore still unreproduced; the harness is committed
for further work rather than claimed as a result.

SAPI note: this lab is mod_php because that is the SAPI the advisory verifies
for request-startup OOM. Under php-fpm a failure in request startup makes the
child exit, which is a different observable and not what this lab measures.

## Both

- The images are built from the official php.net tarballs, with the same
  configure flags for 8.5.11 and 8.5.12. A difference in behaviour is a
  difference in PHP.
- Everything is loopback-only. The labs are for regression testing the two
  fixes and for teaching the request-startup window, not for scanning.
- The advisory text this repo is based on is in
  [`advisory-2026-10-21.md`](advisory-2026-10-21.md).
