"""Parse Nmap XML into structured data for display and export."""

import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None


@dataclass
class HostResult:
    address: Optional[str] = None
    hostname: Optional[str] = None
    state: Optional[str] = None
    os_match: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    ports: List[PortInfo] = field(default_factory=list)


@dataclass
class ScanResult:
    """Top-level result of a parsed Nmap run."""

    scan_type: str = ""
    target: str = ""
    command_line: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    hosts: List[HostResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _text(e: Optional[ET.Element], default: str = "") -> str:
    if e is None:
        return default
    return (e.text or "").strip()


def _get_attr(e: Optional[ET.Element], key: str, default: str = "") -> str:
    if e is None:
        return default
    return e.get(key, default)


def _target_from_nmap_args(args: str) -> str:
    """Extract scan target from Nmap 'args' string (last non-option token)."""
    if not args or not args.strip():
        return ""
    # args is like "nmap -sn -oX /path 192.168.1.0/24" or "nmap 192.168.1.10 -p 80"
    parts = args.split()
    for token in reversed(parts):
        token = token.strip()
        if token and not token.startswith("-") and token != "nmap":
            return token
    return ""


def parse_nmap_xml(xml_path: Path) -> ScanResult:
    """Parse Nmap XML file into a ScanResult. Raises ValueError on parse or I/O errors."""
    path = Path(xml_path)
    try:
        tree = ET.parse(path)
    except OSError as e:
        raise ValueError(f"Cannot read XML file: {e}") from e
    except ET.ParseError as e:
        raise ValueError(f"Invalid Nmap XML: {e}") from e
    root = tree.getroot()
    if root is None:
        raise ValueError("Invalid Nmap XML: empty document")

    command_line = _get_attr(root, "args", "")
    # Finished time from runstats/finished@time (Nmap standard)
    finished_el = root.find("runstats/finished")
    end_time = _get_attr(finished_el, "time") if finished_el is not None else ""
    if not end_time:
        end_time = _get_attr(root, "end", "")
    result = ScanResult(
        command_line=command_line,
        target=_target_from_nmap_args(command_line),
        start_time=_get_attr(root, "start"),
        end_time=end_time or None,
    )

    try:
        for host_el in root.findall(".//host"):
            hr = _parse_host(host_el)
            result.hosts.append(hr)
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Error parsing XML host data: {e}") from e

    return result


def _parse_host(host_el: ET.Element) -> HostResult:
    hr = HostResult()

    # address (explicit check so IP is parsed correctly)
    addr_el = host_el.find("address[@addrtype='ipv4']")
    if addr_el is None:
        addr_el = host_el.find("address[@addrtype='ipv6']")
    if addr_el is not None:
        hr.address = _get_attr(addr_el, "addr")

    # MAC address and vendor (when available, e.g. local network)
    mac_el = host_el.find("address[@addrtype='mac']")
    if mac_el is not None:
        hr.mac_address = _get_attr(mac_el, "addr") or None
        hr.mac_vendor = _get_attr(mac_el, "vendor") or None

    # hostnames
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            hr.hostname = _get_attr(hn, "name")

    # state
    status_el = host_el.find("status")
    if status_el is not None:
        hr.state = _get_attr(status_el, "state")

    # OS
    os_el = host_el.find("os/osmatch")
    if os_el is not None:
        hr.os_match = _get_attr(os_el, "name")

    # ports
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            pi = _parse_port(port_el)
            if pi:
                hr.ports.append(pi)

    return hr


def _parse_port(port_el: ET.Element) -> Optional[PortInfo]:
    portid = _get_attr(port_el, "portid")
    protocol = _get_attr(port_el, "protocol", "tcp")
    if not portid:
        return None
    try:
        port = int(portid)
    except ValueError:
        return None

    state_el = port_el.find("state")
    state = _get_attr(state_el, "state", "unknown") if state_el is not None else "unknown"

    service_el = port_el.find("service")
    service = product = version = extrainfo = None
    if service_el is not None:
        service = _get_attr(service_el, "name") or None
        product = _get_attr(service_el, "product") or None
        version = _get_attr(service_el, "version") or None
        extrainfo = _get_attr(service_el, "extrainfo") or None

    return PortInfo(
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
    )


def load_result_from_json(json_path: Path) -> ScanResult:
    """Load a previously saved ScanResult from JSON. Defensive against malformed data."""
    try:
        raw = json_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Cannot read file: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    hosts_data = data.get("hosts")
    if not isinstance(hosts_data, list):
        hosts_data = []
    hosts = []
    for h in hosts_data:
        if not isinstance(h, dict):
            continue
        ports_data = h.get("ports")
        if not isinstance(ports_data, list):
            ports_data = []
        port_list: List[PortInfo] = []
        for p in ports_data:
            if not isinstance(p, dict):
                continue
            try:
                port_num = int(p.get("port", 0))
            except (TypeError, ValueError):
                continue
            if port_num < 0 or port_num > 65535:
                continue
            port_list.append(
                PortInfo(
                    port=port_num,
                    protocol=p.get("protocol") if isinstance(p.get("protocol"), str) else "tcp",
                    state=p.get("state") if isinstance(p.get("state"), str) else "unknown",
                    service=p.get("service"),
                    product=p.get("product"),
                    version=p.get("version"),
                    extrainfo=p.get("extrainfo"),
                )
            )
        hosts.append(
            HostResult(
                address=h.get("address"),
                hostname=h.get("hostname"),
                state=h.get("state"),
                os_match=h.get("os_match"),
                mac_address=h.get("mac_address"),
                mac_vendor=h.get("mac_vendor"),
                ports=port_list,
            )
        )
    try:
        scan_type_val = data.get("scan_type")
        target_val = data.get("target")
        cmd_val = data.get("command_line")
        start_val = data.get("start_time")
        end_val = data.get("end_time")
    except Exception as e:
        raise ValueError(f"Invalid JSON structure: {e}") from e
    return ScanResult(
        scan_type=scan_type_val if isinstance(scan_type_val, str) else "",
        target=target_val if isinstance(target_val, str) else "",
        command_line=cmd_val if isinstance(cmd_val, str) else "",
        start_time=start_val,
        end_time=end_val,
        hosts=hosts,
    )
