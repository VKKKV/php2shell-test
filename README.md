# php2shell

Reproducible labs for the two PHP request-startup vulnerabilities fixed on
2026-10-21:

| lab | CVE | mechanism | SAPI |
|---|---|---|---|
| `109619` | CVE-2026-109619 | stale global state: a pre-RINIT session encode reuses a freed `BG(serialize)` context | cli-server |
| `109618` | CVE-2026-109618 | OOM corruption: `longjmp` during request startup leaves partially initialised request memory | mod_php |

Each lab builds **8.5.11 (vulnerable) and 8.5.12 (fixed) from the same php.net
tarball with the same configure flags**, so a difference in behaviour is a
difference in PHP, not in the build.

Not a scanner, not an exploit kit, and not a claim of RCE. What each lab proves
and does not prove is in [`docs/claims.md`](docs/claims.md); the official text
it is based on is in [`docs/advisory-2026-10-21.md`](docs/advisory-2026-10-21.md).

## Quick start

```sh
python3 php2shell.py up --only 109619      # builds two CLI images (compiles PHP)
python3 php2shell.py 109619 --php 8.5.11   # -> FIRED, worker exits on zend_mm_heap corrupted
python3 php2shell.py 109619 --php 8.5.12   # -> SURVIVED
python3 php2shell.py 109619 --control      # -> SURVIVED (no OOM, no reuse)

python3 php2shell.py up --only 109618      # builds two mod_php images
python3 php2shell.py 109618 --php 8.5.11 --vector headers
python3 php2shell.py 109618 --php 8.5.12 --vector headers
python3 php2shell.py 109618 --php 8.5.11 --asan --count 1000000  # ASAN build

python3 php2shell.py verify --all          # positive/negative matrix
python3 php2shell.py 109619-rce --fetch    # 8.4.26 RCE (official image), 8.4.27 control
python3 php2shell.py down
```

Requirements: `docker` + `docker compose`, Python >= 3.10. Nothing else. The
first `up` per lab compiles PHP from source (a few minutes each, cached after).

## How 109619 works

1. A multipart POST carries `PHP_SESSION_UPLOAD_PROGRESS` and a file part with
   a 2,000,000-byte filename, plus a 32-byte session ID in the `Cookie` header.
2. PHP parses the body in `php_hash_environment()`, **before**
   `PHP_RINIT_FUNCTION(basic)`. Serialising the progress array exhausts
   `memory_limit=8M` and the fatal bails out before RINIT runs.
3. `BG(serialize)` keeps `level=1` and a pointer to a 64-byte context that
   request shutdown frees.
4. A second multipart POST on the same worker reuses that pointer; the worker
   dies with SIGSEGV (exit 139 in the lab).

The docroot is `/srv/php2shell-docroot` (22 characters), matching the reference
PoC's heap-shaping window. `--control` (small filename) and the 8.5.12 build are
the two controls.

`--sapi fpm` runs the same pair through nginx + php-fpm with
`pm.max_children=1`. It reports `NO REUSE`, for a measured reason: with an
application-level producer the child survives and the instrumented build shows
the stale `BG(serialize)` context (level 1, no free), but under FPM the next
request's upload-progress encode runs *after* RINIT, which has already cleared
it. The cli-server runs that encode before RINIT, which is why the cli lab
fires.

Ported from
[RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf)
(MIT), which stops at memory corruption — no code execution.

### End-to-end RCE (external PoC, pinned)

The public chain from
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
goes further on the official `php:8.4.26-apache` image: it turns the corrupted
shutdown into a heap leak (Set-Cookie), then a libphp leak, then a fake
HashTable whose `pDestructor` is `zif_system`.

```sh
python3 php2shell.py 109619-rce --fetch       # clone the pinned PoC and run
# PROOF (8.4.26): uid=33(www-data) gid=33(www-data) groups=33(www-data)

python3 php2shell.py 109619-rce --php 8.4.27  # fixed control
python3 php2shell.py 109619-rce --php 8.2.34  # vulnerable branch, pre-8.2.35
python3 php2shell.py 109619-rce --php 8.5.12  # latest fixed
```

Measured on the official images:

| target | bug present | 9bie chain |
| --- | --- | --- |
| 8.2.34 | yes — producer requests abort the child (`zend_mm_heap corrupted`) | `HEAP_LEAK_FAILED` |
| 8.4.26 | yes | `PROOF: uid=33(www-data)` |
| 8.4.27 | no | `HEAP_LEAK_FAILED` |
| 8.5.12 | no | `HEAP_LEAK_FAILED` |

8.2.34 is vulnerable per the advisory (fixed in 8.2.35) and the crash confirms
it, but the published chain is shaped for the 8.4.26 heap; porting it to the
8.2 Zend Engine means re-tuning the spray and the 167-byte carrier offset.

The upstream repository has no license file, so it is not vendored: `--fetch`
(or `scripts/fetch-9bie.sh`) clones it into `lab/third_party/9bie` at
`4586f5cc120c82fd468b17469202bac629810ad9` (gitignored). The chain needs
`display_errors=On`, `memory_limit=8M`, `post_max_size=64M` and a single
prefork worker, which is what `templates/php-8426.ini` and
`templates/apache-8426.conf` provide. `--cmd` overrides the default
`id>/out/p1` (14-byte limit; longer commands: write a script and run
`sh</out/c`).

This is CVE-2026-109619 (cross-request state), not 109618.

## How 109618 works

The advisory names three memory amplifiers that stay inside `post_max_size`
while blowing through `memory_limit` during request startup:

- an unrestricted number of headers in one part (`--vector headers`)
- deeply nested field names (`--vector nested`)
- a body without a usable `Content-Length` (`--vector chunked`)

The lab runs them against mod_php with `memory_limit=16M` and
`post_max_size=32M`, and looks for a crash marker on 8.5.11 that is absent on
8.5.12. On this build the `headers` vector reaches the startup OOM on 8.5.11
(`Allowed memory size ... in Unknown on line 0`) and 8.5.12 handles the same body
normally; the corruption itself was not reproduced, so treat this lab as a
trigger harness for the precondition, not as an RCE PoC. An OOM without a crash
is reported as `OOM ONLY`. `--asan` targets an AddressSanitizer mod_php build
with the audit's tracked-allocator setup; it has not caught the corruption yet.

Under php-fpm a startup failure exits the child, which is a different
observable; that is why this lab is mod_php.

## Layout

```
php2shell.py            CLI: up / down / gen / 109619 / 109619-rce / 109618 / verify
templates/
  Dockerfile.cli        php.net tarball -> CLI + session
  Dockerfile.apache     php.net tarball -> mod_php on apache2 prefork
  apache.conf           DocumentRoot /srv/www + the 109618 ini values
  php-8426.ini          official-image ini for the 109619 RCE chain
  apache-8426.conf      single prefork worker for the 109619 RCE chain
  compose.yml           services for profiles 109619 / 109618 / 109619-rce
  webroot/              probe.php (109619), index.php (109618)
docs/
  advisory-2026-10-21.md   official GHSA text, versions, fix commit, path comparison
  claims.md                what each lab proves / does not prove
lab/                    generated by `up`/`gen`, gitignored
```

## References

- CVE-2026-109619 — https://www.cve.org/CVERecord?id=CVE-2026-109619
- CVE-2026-109618 — https://www.cve.org/CVERecord?id=CVE-2026-109618
- GHSA-6wmf-4rv5-p3rp (stale global state)
- GHSA-w8hw-w9fx-j79w (OOM corruption)
- PHP fix: "Avoid state corruption via bailout",
  commit `31c0ea7d7ff1d1fccb6492e52dab544011628065`
- Independent audit: https://github.com/xuehuolll/CVE-2026-109618-109619-audit
- 109619 reference PoC: https://github.com/RemiPelloux/php-session-upload-progress-uaf

## Scope

Loopback only (`127.0.0.1`), no published PHP-FPM port, containers run with
`no-new-privileges`, `read_only` where possible and pids/memory limits. Run it
on machines you own. See [SECURITY.md](SECURITY.md).

MIT.
