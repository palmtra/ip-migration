from __future__ import annotations

import re

VRF_LINE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?:<not set>|\d+:\d+|\d+\.\d+\.\d+\.\d+:\d+)",
    re.MULTILINE,
)
HEADER_NAMES = {"name", "vrf", "default"}


def parse_vrf_names(text: str) -> list[str]:
    names: list[str] = []
    for match in VRF_LINE.finditer(text or ""):
        name = match.group("name")
        if name.lower() in HEADER_NAMES:
            continue
        if name not in names:
            names.append(name)
    return names


def parse_vsys_names(text: str) -> list[str]:
    names: list[str] = []
    blob = text or ""
    vsys_xml = re.search(r"<vsys>([\s\S]*)</vsys>", blob, re.IGNORECASE)
    if vsys_xml:
        for match in re.finditer(
            r'<entry name="([^"]+)">\s*<(?:display-name|import|zone|rulebase)\b',
            vsys_xml.group(1),
            re.IGNORECASE,
        ):
            name = match.group(1)
            if name not in names:
                names.append(name)
    for match in re.finditer(r"\bvsys\d+\b", blob, re.IGNORECASE):
        name = match.group(0)
        if name not in names:
            names.append(name)
    in_table = False
    for line in blob.splitlines():
        if re.search(r"VSYS\s+Name", line, re.IGNORECASE):
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if not parts or parts[0].lower() in {"----------", "vsys"}:
                continue
            if re.match(r"^[-+]+$", parts[0]):
                continue
            if parts[0] not in names:
                names.append(parts[0])
    if not names:
        names = ["vsys1"]
    return names
