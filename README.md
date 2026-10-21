# php2shell-test

Self-contained PHP session-poisoning lab plus four exploit chains that are
verified end-to-end on stock images. One stdlib-only Python CLI, two pinned
containers, no runtime dependencies.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![PHP](https://img.shields.io/badge/PHP-8.2.34-777bb4.svg)
![Docker Compose](https://img.shields.io/badge/docker%20compose-lab-2496ed.svg)

Not a scanner and not a CVE claim. It is a reproducible lab and an honest
record of what did and did not work on `php:8.2.34-fpm` / `nginx:1.31.7-alpine`.

## Quick start

```sh
git clone https://github.com/VKKKV/php2shell-test.git
cd php2shell-test

python3 php2shell.py up                 # render lab/, compose up --wait (127.0.0.1:18081)
python3 php2shell.py rce --cmd 'id'     # -> uid=33(www-data) ...
python3 php2shell.py race --stock-cleanup   # -> executes while the body is still streaming
python3 php2shell.py mismatch           # -> __destruct marker in the php container
python3 php2shell.py uaf                # -> R:1500 resolved to: integer
python3 php2shell.py down               # containers + volumes
```

Requirements: `docker` + `docker compose`, Python ≥ 3.10. Nothing else.

## What is verified

| chain | mechanism | proof |
|---|---|---|
| `rce` | fixation + filename injection → `include()` of the session file | command output (`uid=33(www-data)`) |
| `race` | same poison, include fired while the body is still streaming | command output plus `in flight: N/M bytes sent` |
| `mismatch` | `php_serialize` writer + `php` reader → injected object unserialized | `Gadget::__destruct()` writes `/tmp/gadget-hit` |
| `uaf` | `unserialize()` var_destroy/`__destruct` reentry read-after-free | `R:1500` resolves to `integer` instead of `bool(false)` |

`rce` is the deterministic version: it needs `session.upload_progress.cleanup=Off`.
`race` is the realistic one: it also works with the stock `cleanup=On`, because the
include is served by a second worker while the first is still reading the body.
Run it with `--stock-cleanup` to flip the lab to `cleanup=On`, prove it, and restore.

`mismatch` deliberately does not trust the `Failed to decode session object`
warning: any malformed session can produce it. The chain passes only when the
marker file exists. The read request is a plain GET, because a multipart POST
would open the session during RINIT, before userland classes exist, and the
injected object could only become `__PHP_Incomplete_Class`.

The UAF check is behavioural on the stock image. The ASAN trace (heap
use-after-free read at `var_unserializer.c:850`, freed in `var_destroy`) comes
from a sanitizer build (`-fsanitize=address`, `USE_ZEND_ALLOC=0`).

## Not reproduced

The upload_progress "UAF → `zend_call_function`" RCE did not reproduce here on
`php:8.2.34-fpm` with symbols taken from that build: no code execution, no
crash, no worker change. The independent audit
[xuehuolll/CVE-2026-109618-109619-audit](https://github.com/xuehuolll/CVE-2026-109618-109619-audit)
agrees for stock builds. CVE-2026-109618 / 109619 are RESERVED at cve.org; the
number-to-mechanism mappings circulating in community repos are unconfirmed.

## Lab

```
host                                 compose network
127.0.0.1:18081 ──► nginx:80 ──► php-fpm:9000   (never published)
                       │               │
                       └── /var/www/html ── read-only bind of lab/webroot
                                       └── sessions: tmpfs /tmp/sessions
```

- Loopback-only publish; php-fpm has no host port.
- `read_only`, `no-new-privileges`, pids/memory limits; the vulnerability is
  in the PHP config and app code, not in container isolation.
- Images pinned: `php:8.2.34-fpm`, `nginx:1.31.7-alpine`.
- nginx streams request bodies (`fastcgi_request_buffering off`) and allows
  16m (`client_max_body_size`). With the stock 1m limit the race body is
  rejected with 413 before PHP ever sees the multipart.
- `/healthz` is a static 200 for the nginx healthcheck. Polling `index.php`
  instead created a fresh empty session file every 2s.
- `lab/` is generated from `templates/` and gitignored. `up` re-creates the
  containers from what is on disk; `--regen` overwrites hand edits.
- Compose project is `php2shell-<sha1 of checkout path>`, so clones do not
  collide. Override with `PHP2SHELL_PROJECT`.

| command | purpose |
|---|---|
| `up [--regen]` | render `lab/`, `compose up -d --wait --force-recreate` |
| `gen [--regen]` | render `lab/` only (CI, `docker compose config`) |
| `down` | `compose down -v --remove-orphans`; safe to repeat |
| `rce [--cmd CMD] [--sid SID]` | poison + include; command is base64-encoded |
| `race [--cmd CMD] [--sid SID] [--size N] [--stock-cleanup]` | poison + include while the body is still streaming |
| `mismatch [--class CLS] [--sid SID]` | object injection, marker-verified |
| `uaf` | run the `R:1500` trigger inside the php container |

Global options go before the subcommand: `--port N` /
`PHP2SHELL_HTTP_PORT` / `lab/.http-port` (default `18081`), `-v`, `-q`.
Ports, `--sid` and `--class` are validated before they reach a URL, cookie,
multipart header or container path.

## When it works

Every row has to hold. The first one that fails kills the chain — this is why
"PHP with upload_progress" is not the same thing as "exploitable".

| # | condition | stock value | how to check |
|---|---|---|---|
| 1 | PHP behind a web SAPI (fpm / apache / cgi) | — | `php_sapi_name()`, `X-Powered-By` |
| 2 | `session.upload_progress.enabled=On` | On | `php -i` |
| 3 | client-supplied session IDs accepted (`session.use_strict_mode=0`) | 0 | send `Cookie: PHPSESSID=<chosen>`; unchanged in the response means accepted |
| 4 | `session.save_handler=files` | files | redis/memcached means there is no file to include |
| 5 | `session.save_path` known and readable by the web user | `/tmp`, `/var/lib/php/sessions` | `php -i`, `ls -l` |
| 6 | app `include`/`require`s an attacker-steerable path | — | source review; without it, poisoning only writes bytes |
| 7 | body fits `post_max_size` and the server body limit | 8M / nginx 1m | 413, or a silently empty `$_POST` |
| 8 | for `cleanup=On`: the web server streams the body | nginx buffers | `fastcgi_request_buffering off` |

`session.use_only_cookies` does not appear in the table on purpose: the SID
travels in the `Cookie` header either way, so turning it on changes nothing.

The interesting row is 8. A buffering front end (nginx's default) hands the
whole body to PHP at once, so the window shrinks to the parse time and the race
becomes impractical; a streaming front end keeps it open for the whole upload.
`cleanup=On` alone does not close the window, it only removes the progress entry
when the request ends.

### Where the sink lives

PHP gives you the write; the application has to give you the read. Typical
`include` sinks that take a path from the request:

- template / theme / language loaders: `?lang=`, `?template=`, `?theme=`, `?view=`
- module and page routers that concatenate: `index.php?module=news`
- file viewers: `download.php?file=`, `preview.php?path=`, log readers
- image / thumbnail helpers: `thumb.php?src=`
- plugin and addon loaders: `?plugin=`, `?addon=`

Probe a candidate with a harmless path and watch for
`include(...): Failed to open stream` — the warning names the function and the
resolved path, so it tells you whether the parameter reaches an `include` at
all. No payload is needed for that step.

### What this does not bypass

Session poisoning only supplies a file whose bytes the attacker controls. It
relaxes nothing about the include itself:

- an allowlist or a name→path map means the parameter never reaches `include`
- a suffix appended by the app (`include($p . '.php')`) cannot be satisfied:
  the session file is `sess_<sid>`, with no extension
- `open_basedir` that excludes the session directory blocks the read
- `session.save_handler=redis|memcached` means there is no file at all
- `session.upload_progress.enabled=Off` means nothing gets written
- `session.use_strict_mode=On` without an app-issued SID means the SID is replaced

It replaces log poisoning, upload tricks and `php://input` as the *write* half
of an LFI, and it is worth trying when the app has no upload feature and the
log path is unknown or unreadable.

## Mitigation

`session.upload_progress.enabled = Off` breaks every chain in this repo: both
`rce` and `mismatch` then fail with `no session file was written`. Restore the
lab with `up --regen`. `session.use_strict_mode = On` also kills the fixation
step, at the cost of rejecting client-generated session IDs.

`session.upload_progress.cleanup = On` (the stock default) is **not** a
mitigation — `race --stock-cleanup` executes while the body is still streaming
and then restores the lab. What does help at the edge: buffer the request body
before PHP sees it, or block multipart bodies carrying
`PHP_SESSION_UPLOAD_PROGRESS` (needs body inspection and breaks legitimate
upload progress; community rule sets exist for
[Apache/ModSecurity, lighttpd, Caddy](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC)
and as [Sigma/Suricata/YARA](https://github.com/mikensec/php2shell-lab)).

## Layout

```
php2shell.py            stdlib-only CLI (render lab, run chains)
templates/              source of truth: PHP, nginx, compose, php.ini
lab/                    generated at runtime, gitignored
```

## Development

```sh
pip install ruff
ruff check . && ruff format --check .
python3 php2shell.py up && python3 php2shell.py rce && python3 php2shell.py mismatch
python3 php2shell.py race --stock-cleanup && python3 php2shell.py uaf
```

## Scope

- `rce` needs a target-controlled `include()`; session poisoning alone only
  writes bytes to a session file.
- Deterministic poisoning needs `session.upload_progress.cleanup=Off` (lab
  php.ini). With stock `cleanup=On` the same bytes are only on disk while the
  body is being read, so `race` is the chain that applies — and it needs the
  front end to stream the body. An aborted upload still did not poison.
- `mismatch` needs a gadget class in the reading app; the demo `Gadget` only
  writes a marker file.
- Runs on infrastructure you own. See [SECURITY.md](SECURITY.md).

## License

MIT ([LICENSE](LICENSE)).
