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


def parse_panorama_devices(text: str) -> list[dict[str, str | bool]]:
    """Extract managed firewall serials from Panorama `show devices all` output."""
    blob = text or ""
    by_serial: dict[str, dict[str, str | bool]] = {}

    def add(serial: str, hostname: str = "", connected: bool | None = None) -> None:
        serial = (serial or "").strip()
        if not re.fullmatch(r"\d{11,16}", serial):
            return
        entry = by_serial.setdefault(serial, {"serial": serial, "hostname": "", "connected": True})
        if hostname and not entry.get("hostname"):
            entry["hostname"] = hostname.strip()
        if connected is False:
            entry["connected"] = False

    for match in re.finditer(
        r'<entry name="(\d{11,16})"(?:[^>]*)>(.*?)</entry>',
        blob,
        re.IGNORECASE | re.DOTALL,
    ):
        block = match.group(2)
        if not re.search(r"<(?:serial|hostname|connected|ha|family|model)\b", block, re.IGNORECASE):
            continue
        host_m = re.search(r"<hostname>([^<]+)</hostname>", block, re.IGNORECASE)
        conn_m = re.search(r"<connected>([^<]+)</connected>", block, re.IGNORECASE)
        connected = None
        if conn_m:
            connected = conn_m.group(1).strip().lower() in {"yes", "connected", "true"}
        add(match.group(1), host_m.group(1) if host_m else "", connected)

    for match in re.finditer(r"<serial>(\d{11,16})</serial>", blob, re.IGNORECASE):
        add(match.group(1))
    for match in re.finditer(r'"serial"\s*:\s*"(\d{11,16})"', blob):
        add(match.group(1))
    for match in re.finditer(r'"hostname"\s*:\s*"([^"]+)".{0,200}?"serial"\s*:\s*"(\d{11,16})"', blob, re.DOTALL):
        add(match.group(2), match.group(1))
    for match in re.finditer(r'"serial"\s*:\s*"(\d{11,16})".{0,200}?"hostname"\s*:\s*"([^"]+)"', blob, re.DOTALL):
        add(match.group(1), match.group(2))

    devices = []
    for serial, entry in by_serial.items():
        if entry.get("connected") is False:
            continue
        devices.append(entry)
    return devices
