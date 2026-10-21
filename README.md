# php2shell-test

Self-contained PHP session-poisoning lab plus three exploit chains that are
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
python3 php2shell.py mismatch           # -> __destruct marker in the php container
python3 php2shell.py uaf                # -> R:1500 resolved to: integer
python3 php2shell.py down               # containers + volumes
```

Requirements: `docker` + `docker compose`, Python ≥ 3.10. Nothing else.

## What is verified

| chain | mechanism | proof |
|---|---|---|
| `rce` | fixation + filename injection → `include()` of the session file | command output (`uid=33(www-data)`) |
| `mismatch` | `php_serialize` writer + `php` reader → injected object unserialized | `Gadget::__destruct()` writes `/tmp/gadget-hit` |
| `uaf` | `unserialize()` var_destroy/`__destruct` reentry read-after-free | `R:1500` resolves to `integer` instead of `bool(false)` |

`mismatch` deliberately does not trust the `Failed to decode session object`
warning: any malformed session can produce it. The chain passes only when the
marker file exists. The read request is a plain GET, because a multipart POST
would open the session during RINIT, before userland classes exist, and the
injected object could only become `__PHP_Incomplete_Class`.

The UAF check is behavioural on the stock image; the ASAN trace (heap
use-after-free read at `var_unserializer.c:850`, freed in `var_destroy`) comes
from a sanitizer build and is recorded in
[docs/verification.md](docs/verification.md).

## Not reproduced

The upload_progress "UAF → `zend_call_function`" RCE did not reproduce here on
`php:8.2.34-fpm` with symbols taken from that build: no code execution, no
crash, no worker change. The independent audit
[xuehuolll/CVE-2026-109618-109619-audit](https://github.com/xuehuolll/CVE-2026-109618-109619-audit)
agrees for stock builds. CVE-2026-109618 / 109619 are RESERVED at cve.org; the
number-to-mechanism mappings circulating in community repos are unconfirmed.
Mechanism notes and what we tested: [docs/mechanisms.md](docs/mechanisms.md).

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
| `mismatch [--class CLS] [--sid SID]` | object injection, marker-verified |
| `uaf` | run the `R:1500` trigger inside the php container |

Global options go before the subcommand: `--port N` /
`PHP2SHELL_HTTP_PORT` / `lab/.http-port` (default `18081`), `-v`, `-q`.
Ports, `--sid` and `--class` are validated before they reach a URL, cookie,
multipart header or container path.

## Mitigation

`session.upload_progress.enabled = Off` breaks every chain in this repo
(verified, recipe in [docs/verification.md](docs/verification.md)). Community
edge/WAF rule sets and detection signals are listed in
[docs/mechanisms.md](docs/mechanisms.md). Blocking multipart bodies with
`PHP_SESSION_UPLOAD_PROGRESS` works but needs body inspection and breaks
legitimate upload progress.

## Layout

```
php2shell.py            stdlib-only CLI (render lab, run chains)
templates/              source of truth: PHP, nginx, compose, php.ini
tests/                  unit tests + `-m integration` full cycle
docs/mechanisms.md      what each primitive does, what we could not reproduce
docs/verification.md    command-by-command record, versions, ASAN trace
lab/                    generated at runtime, gitignored
```

## Development

```sh
pip install ruff pytest
ruff check . && ruff format --check .
pytest -q                 # unit tests, no docker
pytest -q -m integration  # up → rce → mismatch → uaf → down
```

## Scope

- `rce` needs a target-controlled `include()`; session poisoning alone only
  writes bytes to a session file.
- Deterministic poisoning needs `session.upload_progress.cleanup=Off` (lab
  php.ini). Stock `cleanup=On` is not enough for this chain, and an aborted
  upload did not poison through nginx + php-fpm in our tests.
- `mismatch` needs a gadget class in the reading app; the demo `Gadget` only
  writes a marker file.
- Runs on infrastructure you own. See [SECURITY.md](SECURITY.md).

## License

MIT ([LICENSE](LICENSE)).
