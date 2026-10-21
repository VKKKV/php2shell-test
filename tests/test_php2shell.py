"""Unit tests for the stdlib-only CLI; integration tests need Docker.

pytest                 # unit only
pytest -m integration  # full up -> rce -> mismatch -> uaf -> down
"""

from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("php2shell_cli", ROOT / "php2shell.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load()


# --------------------------------------------------------------------------
# multipart framing
# --------------------------------------------------------------------------
def test_multipart_framing_and_length():
    body, boundary = cli.build_multipart("payload", "abc123")

    assert len(boundary) == 32 and boundary.isalnum()
    assert body.count(f"--{boundary}".encode()) == 4
    assert body.endswith(f"--{boundary}--\r\n".encode())
    assert b'name="PHPSESSID"\r\n\r\nabc123\r\n' in body
    assert body.index(b'name="PHPSESSID"') < body.index(b"PHP_SESSION_UPLOAD_PROGRESS")
    assert body.index(b"PHP_SESSION_UPLOAD_PROGRESS") < body.index(b'filename="payload"')
    # Content-Length must be the byte length of what is sent on the wire.
    assert str(len(body)).isdigit()


def test_multipart_escapes_quote_and_backslash():
    body, _ = cli.build_multipart('a"b\\c', "sid")
    assert b'filename="a\\"b\\\\c"' in body


@pytest.mark.parametrize("bad", ["a\rb", "a\nb", "na\u00efve"])
def test_multipart_rejects_crlf_and_non_ascii(bad):
    with pytest.raises(cli.LabError):
        cli.build_multipart(bad, "sid")


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------
@pytest.mark.parametrize("sid", ["poc26rce0000000000000000", "a", "A,b-c,9" * 10])
def test_sid_accepts_safe_values(sid):
    assert cli.validate_sid(sid) == sid


@pytest.mark.parametrize("sid", ["", "a b", "a/b", "a|b", "x" * 129, "../etc/passwd"])
def test_sid_rejects_unsafe_values(sid):
    with pytest.raises(cli.LabError):
        cli.validate_sid(sid)


@pytest.mark.parametrize("name", ["Gadget", "_x", "A1_b"])
def test_class_accepts_identifiers(name):
    assert cli.validate_class(name) == name


@pytest.mark.parametrize("name", ["1Gadget", "Gad get", "Gadget;", "", "a\\b"])
def test_class_rejects_non_identifiers(name):
    with pytest.raises(cli.LabError):
        cli.validate_class(name)


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cmd",
    [
        "id",
        'echo "hello world"',
        "printf 'a\\\\b'",
        "echo $HOME; touch /tmp/x",
        "printf 'multi\nline'",
        "echo 'héllo'",
    ],
)
def test_rce_payload_roundtrips_any_command(cmd):
    payload = cli.build_rce_payload(cmd)
    assert payload.isascii()
    assert payload.startswith("<?php") and payload.endswith("?>")
    encoded = payload.split("base64_decode('", 1)[1].split("')", 1)[0]
    assert base64.b64decode(encoded).decode("utf-8") == cmd
    # Nothing but the base64 blob may carry user input into the payload.
    assert '"' not in payload and "\\" not in payload


def test_injection_uses_byte_length():
    assert cli.build_injection("Gadget") == 'x|O:6:"Gadget":0:{}'


# --------------------------------------------------------------------------
# lab rendering / ports
# --------------------------------------------------------------------------
def test_generate_lab_pins_images_and_loopback(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "LAB", tmp_path / "lab")
    monkeypatch.setattr(cli, "PORT_FILE", tmp_path / "lab" / ".http-port")
    written = cli.generate_lab(18099)
    compose = (tmp_path / "lab" / "docker-compose.yml").read_text()

    assert written and all(p.is_file() for p in written)
    assert "127.0.0.1:18099:80" in compose
    assert "container_name" not in compose
    assert "9001:9000" not in compose and 'ports:\n      - "9001' not in compose
    assert "php:8.2.34-fpm" in compose and "nginx:1.31.7-alpine" in compose
    assert "no-new-privileges:true" in compose and "read_only: true" in compose
    assert (tmp_path / "lab" / "webroot" / "vuln.php").is_file()


def test_generate_lab_keeps_user_edits_unless_regen(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "LAB", tmp_path / "lab")
    monkeypatch.setattr(cli, "PORT_FILE", tmp_path / "lab" / ".http-port")
    cli.generate_lab(18099)
    ini = tmp_path / "lab" / "php.ini"
    ini.write_text("# user edit\n")

    cli.generate_lab(18099)
    assert ini.read_text() == "# user edit\n"

    # The compose file always tracks the requested port.
    cli.generate_lab(18100)
    compose = (tmp_path / "lab" / "docker-compose.yml").read_text()
    assert "127.0.0.1:18100:80" in compose
    assert ini.read_text() == "# user edit\n"

    cli.generate_lab(18100, regen=True)
    assert "display_errors = On" in ini.read_text()


def test_resolve_port_precedence(tmp_path, monkeypatch):
    port_file = tmp_path / ".http-port"
    monkeypatch.setattr(cli, "PORT_FILE", port_file)
    monkeypatch.delenv("PHP2SHELL_HTTP_PORT", raising=False)

    assert cli.resolve_port(None) == cli.DEFAULT_PORT
    port_file.write_text("18123\n")
    assert cli.resolve_port(None) == 18123
    monkeypatch.setenv("PHP2SHELL_HTTP_PORT", "18124")
    assert cli.resolve_port(None) == 18124
    assert cli.resolve_port(18125) == 18125
    monkeypatch.setenv("PHP2SHELL_HTTP_PORT", "nope")
    with pytest.raises(cli.LabError):
        cli.resolve_port(None)


def test_project_name_is_per_checkout(monkeypatch):
    monkeypatch.delenv("PHP2SHELL_PROJECT", raising=False)
    name = cli.project_name()
    assert name.startswith("php2shell-") and len(name) == len("php2shell-") + 8
    monkeypatch.setenv("PHP2SHELL_PROJECT", "custom")
    assert cli.project_name() == "custom"


# --------------------------------------------------------------------------
# integration (docker required): pytest -m integration
# --------------------------------------------------------------------------
@pytest.mark.integration
def test_full_chain_cycle(tmp_path):
    env = dict(os.environ, PHP2SHELL_PROJECT="php2shell-pytest")
    base = [sys.executable, str(ROOT / "php2shell.py"), "--port", "18088"]

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            base + list(args), cwd=ROOT, capture_output=True, text=True, env=env, timeout=600
        )

    try:
        assert run("up").returncode == 0
        out = run("rce", "--cmd", 'echo "quoted" && id')
        assert out.returncode == 0, out.stdout + out.stderr
        assert "RCE via include" in out.stdout and "uid=" in out.stdout
        assert run("mismatch").returncode == 0
        assert run("uaf").returncode == 0
    finally:
        run("down")
