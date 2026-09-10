from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)", re.IGNORECASE | re.MULTILINE)
PROMPT_RE = re.compile(r"^(?P<host>\S+)#(?P<cmd>show\s+.+?)\s*$", re.IGNORECASE)
END_RE = re.compile(r"^end\s*$", re.IGNORECASE | re.MULTILINE)


def split_eos_dump(text: str) -> tuple[str, str, list[tuple[str, str]]]:
    """Split a mixed running-config + CLI dump into hostname, config, show outputs."""
    blob = text or ""
    host_match = HOSTNAME_RE.search(blob)
    hostname = host_match.group(1) if host_match else "device"
    parts = END_RE.split(blob, maxsplit=1)
    running = parts[0].rstrip() + "\nend\n"
    remainder = parts[1] if len(parts) > 1 else ""
    commands: list[tuple[str, str]] = []
    current_cmd: str | None = None
    buf: list[str] = []
    for line in remainder.splitlines():
        prompt = PROMPT_RE.match(line.strip())
        if prompt:
            if current_cmd is not None:
                commands.append((current_cmd, "\n".join(buf).rstrip() + "\n"))
            current_cmd = prompt.group("cmd").strip()
            hostname = prompt.group("host") or hostname
            buf = []
            continue
        if current_cmd is not None:
            buf.append(line)
    if current_cmd is not None:
        commands.append((current_cmd, "\n".join(buf).rstrip() + "\n"))
    return hostname, running, commands


def artifact_from_eos_dump(text: str, device: str | None = None) -> dict[str, Any]:
    hostname, running, commands = split_eos_dump(text)
    name = device or hostname
    cmd_names = ["show running-config"] + [item[0] for item in commands]
    stdout = [running] + [item[1] for item in commands]
    return {
        "device": name,
        "show_commands": {
            "commands": cmd_names,
            "stdout": stdout,
            "invocation": {"module_args": {"commands": cmd_names}},
        },
        "meta": {
            "device": name,
            "platform": "arista.eos.eos",
            "vendor": "arista",
            "role": "switch",
            "source": "eos-dump",
        },
    }


def write_eos_dump_artifact(dump_path: Path, artifacts_dir: Path, device: str | None = None) -> Path:
    payload = artifact_from_eos_dump(dump_path.read_text(encoding="utf-8"), device=device)
    name = str(payload["device"])
    device_dir = artifacts_dir / name
    device_dir.mkdir(parents=True, exist_ok=True)
    (device_dir / "meta.json").write_text(json.dumps(payload["meta"], indent=2) + "\n", encoding="utf-8")
    (device_dir / "show_commands.json").write_text(
        json.dumps(payload["show_commands"], indent=2) + "\n", encoding="utf-8"
    )
    return device_dir
