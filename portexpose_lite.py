#!/usr/bin/env python3
"""portexpose-lite: read Docker Compose files and flag published ports.

Read-only. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# Data-store and Docker API ports treated as sensitive in lite.
# (Web admin ports such as 8080/3000 are not treated as sensitive here.)
SENSITIVE_PORTS = {
    2375: "Docker API",
    2376: "Docker API",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

DEFAULT_COMPOSE_NAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
)

DEMO_COMPOSE = """\
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"
  redis:
    image: redis:7
    ports:
      - "6379:6379"
  web:
    image: nginx:alpine
    ports:
      - "127.0.0.1:8080:80"
  adminer:
    image: adminer
    ports:
      - "0.0.0.0:8081:8080"
"""


class ComposeError(ValueError):
    """The file could not be parsed as a Compose YAML subset."""


# ---------------------------------------------------------------------------
# Minimal YAML subset (mappings, lists, quoted/plain scalars, comments)
# ---------------------------------------------------------------------------

def _unquote(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        inner = raw[1:-1]
        if raw[0] == '"':
            inner = bytes(inner, "utf-8").decode("unicode_escape") if "\\" in inner else inner
        return inner
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1].replace("''", "'")
    return raw


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _split_flow_items(body: str) -> list:
    items = []
    buf = []
    depth = 0
    in_single = in_double = False
    for ch in body:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif ch in "[{" and not in_single and not in_double:
            depth += 1
            buf.append(ch)
        elif ch in "]}" and not in_single and not in_double:
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0 and not in_single and not in_double:
            items.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _parse_flow(raw: str) -> Any:
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in _split_flow_items(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        mapping = {}
        if inner:
            for item in _split_flow_items(inner):
                if ":" not in item:
                    raise ComposeError("invalid flow mapping item %r" % item)
                k, rest = item.split(":", 1)
                mapping[_unquote(k.strip())] = _parse_scalar(rest.strip())
        return mapping
    return None


def _parse_scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "" or s in ("null", "~", "Null", "NULL"):
        return None
    if s.startswith("[") or s.startswith("{"):
        flowed = _parse_flow(s)
        if flowed is not None:
            return flowed
    if s in ("true", "True", "TRUE", "yes", "Yes", "on"):
        return True
    if s in ("false", "False", "FALSE", "no", "No", "off"):
        return False
    if re.fullmatch(r"-?\d+", s):
        try:
            return int(s)
        except ValueError:
            return s
    return _unquote(s)


def parse_simple_yaml(text: str) -> Any:
    """Parse a Compose-sized YAML subset. No anchors, tags, or merge keys."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("\ufeff"):
        text = text[1:]
    raw_lines = text.split("\n")
    lines: List[Tuple[int, int, str]] = []  # lineno, indent, content
    for n, line in enumerate(raw_lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        expanded = line.replace("\t", "  ")
        content = _strip_comment(expanded)
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        lines.append((n, indent, content.strip()))

    idx = 0

    def parse_block(min_indent: int) -> Any:
        nonlocal idx
        if idx >= len(lines):
            return None
        _lineno, indent, content = lines[idx]
        if indent < min_indent:
            return None
        if content.startswith("- " ) or content == "-":
            return parse_list(indent)
        return parse_map(indent)

    def parse_map(indent: int) -> Dict[str, Any]:
        nonlocal idx
        result: Dict[str, Any] = {}
        while idx < len(lines):
            lineno, ind, content = lines[idx]
            if ind < indent:
                break
            if ind > indent:
                raise ComposeError("unexpected indentation at line %s" % lineno)
            if content.startswith("- ") or content == "-":
                raise ComposeError("list item where a mapping key is expected (line %s)" % lineno)
            if ":" not in content:
                raise ComposeError("expected 'key:' at line %s" % lineno)
            key, rest = content.split(":", 1)
            key = _unquote(key.strip())
            rest = rest.strip()
            idx += 1
            if rest in ("|", ">", ">-", "|-"):
                raise ComposeError("multiline YAML scalars are not supported (line %s)" % lineno)
            if rest:
                result[key] = _parse_scalar(rest)
            else:
                if idx < len(lines) and lines[idx][1] > indent:
                    result[key] = parse_block(indent + 1)
                else:
                    result[key] = None
        return result

    def parse_list(indent: int) -> List[Any]:
        nonlocal idx
        result: List[Any] = []
        while idx < len(lines):
            lineno, ind, content = lines[idx]
            if ind < indent:
                break
            if ind > indent:
                raise ComposeError("unexpected indentation at line %s" % lineno)
            if not (content.startswith("- ") or content == "-"):
                break
            item = content[1:].strip()
            idx += 1
            if not item:
                if idx < len(lines) and lines[idx][1] > indent:
                    result.append(parse_block(indent + 1))
                else:
                    result.append(None)
            elif item.startswith("{") or (":" in item and not item.startswith("[")
                                          and not _looks_like_port_string(item)):
                # inline or compact mapping: "target: 80" or "published: 8080"
                # For long-syntax list items, the first key may be on the dash line
                # and further keys may be on following more-indented lines.
                if ":" in item and not item.startswith("{"):
                    k, rest = item.split(":", 1)
                    mapping = {_unquote(k.strip()): _parse_scalar(rest.strip()) if rest.strip() else None}
                    if idx < len(lines) and lines[idx][1] > indent:
                        extra = parse_map(lines[idx][1])
                        if isinstance(extra, dict):
                            mapping.update(extra)
                    result.append(mapping)
                else:
                    result.append(_parse_scalar(item))
            else:
                result.append(_parse_scalar(item))
        return result

    if not lines:
        return {}
    doc = parse_block(lines[0][1])
    if idx < len(lines):
        # allow a trailing document
        pass
    return doc if doc is not None else {}


def _looks_like_port_string(item: str) -> bool:
    """True for Compose short port strings, which contain colons but are not maps."""
    s = item.strip().strip("\"'")
    if s.startswith("["):  # IPv6 "[::]:8080:80"
        return True
    # "5432:5432", "127.0.0.1:8080:80", "8000-8002:8000-8002/tcp"
    return bool(re.match(r"^(?:\d+(?:-\d+)?|\d+\.\d+\.\d+\.\d+):", s)) or bool(
        re.fullmatch(r"\d+(?:-\d+)?(?:/(?:tcp|udp))?", s)
    )


# ---------------------------------------------------------------------------
# Port parsing and rating
# ---------------------------------------------------------------------------

def _parse_ip(raw: str) -> Optional[ipaddress._BaseAddress]:
    raw = (raw or "").strip().strip("[]")
    if raw in ("", "*", "0.0.0.0", "::"):
        return None  # wildcard / unspecified, represented as None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def classify_ip(raw: str) -> str:
    """Return 'wildcard', 'loopback', 'private', or 'public'."""
    text = (raw or "").strip().strip("[]")
    if text in ("", "*", "0.0.0.0", "::"):
        return "wildcard"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "wildcard"
    if ip.is_unspecified:
        return "wildcard"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private and not ip.is_loopback:
        return "private"
    return "public"


def _expand_range(spec: str) -> List[int]:
    spec = str(spec).strip()
    if "-" in spec:
        a, b = spec.split("-", 1)
        start, end = int(a), int(b)
        if end < start or end - start > 1000:
            raise ComposeError("port range %s is invalid or too large" % spec)
        return list(range(start, end + 1))
    return [int(spec)]


def parse_short_port(elem: str) -> List[Dict[str, Any]]:
    """Parse Compose short syntax into one dict per published host port."""
    raw = str(elem).strip()
    proto = "tcp"
    if "/" in raw:
        raw, proto = raw.rsplit("/", 1)
        proto = proto.lower()
    host_ip = "0.0.0.0"
    # Bracketed IPv6: [::]:8080:80 or [::1]:8080:80
    if raw.startswith("["):
        close = raw.find("]")
        if close == -1:
            raise ComposeError("unclosed IPv6 address in port mapping %r" % elem)
        host_ip = raw[1:close]
        rest = raw[close + 1:]
        if rest.startswith(":"):
            rest = rest[1:]
        parts = rest.split(":")
    else:
        parts = raw.split(":")
        if len(parts) == 3:
            host_ip, host, container = parts[0], parts[1], parts[2]
            parts = [host, container]
        elif len(parts) == 1:
            # container port only; Docker publishes it on 0.0.0.0 with a random host port
            host_ip = "0.0.0.0"
            parts = [parts[0], parts[0]]
            # Mark random host port
            return [
                {
                    "host_ip": host_ip,
                    "host_port": None,
                    "container_port": p,
                    "protocol": proto,
                    "random_host_port": True,
                }
                for p in _expand_range(parts[1])
            ]
        elif len(parts) != 2:
            raise ComposeError("cannot parse port mapping %r" % elem)
    host_spec, container_spec = parts[0], parts[1]
    host_ports = _expand_range(host_spec)
    container_ports = _expand_range(container_spec)
    if len(host_ports) != len(container_ports):
        # Docker maps ranges of equal length; if not, still zip what we can
        if len(host_ports) != len(container_ports):
            raise ComposeError("host/container port range length mismatch in %r" % elem)
    out = []
    for hp, cp in zip(host_ports, container_ports):
        out.append(
            {
                "host_ip": host_ip or "0.0.0.0",
                "host_port": hp,
                "container_port": cp,
                "protocol": proto,
                "random_host_port": False,
            }
        )
    return out


def parse_long_port(elem: Dict[str, Any]) -> List[Dict[str, Any]]:
    if str(elem.get("mode") or "ingress") not in ("host", "ingress", ""):
        # ignore long-syntax setup that is not a published port
        pass
    published = elem.get("published")
    target = elem.get("target")
    proto = str(elem.get("protocol") or "tcp").lower()
    host_ip = str(elem.get("host_ip") or "0.0.0.0").strip() or "0.0.0.0"
    if published is None and target is None:
        return []
    if published is None:
        # published omitted: similar to container-only short syntax
        return [
            {
                "host_ip": host_ip,
                "host_port": None,
                "container_port": p,
                "protocol": proto,
                "random_host_port": True,
            }
            for p in _expand_range(str(target))
        ]
    host_ports = _expand_range(str(published))
    container_ports = _expand_range(str(target if target is not None else published))
    if len(host_ports) != len(container_ports):
        raise ComposeError("long-syntax port range length mismatch: %r" % elem)
    return [
        {
            "host_ip": host_ip,
            "host_port": hp,
            "container_port": cp,
            "protocol": proto,
            "random_host_port": False,
        }
        for hp, cp in zip(host_ports, container_ports)
    ]


def parse_port_entry(elem: Any) -> List[Dict[str, Any]]:
    if elem is None:
        return []
    if isinstance(elem, dict):
        return parse_long_port(elem)
    if isinstance(elem, (int, float)):
        return parse_short_port(str(int(elem)))
    return parse_short_port(str(elem))


def rate_binding(binding: Dict[str, Any]) -> Dict[str, Any]:
    kind = classify_ip(str(binding.get("host_ip") or "0.0.0.0"))
    host_port = binding.get("host_port")
    sensitive = SENSITIVE_PORTS.get(int(host_port)) if host_port is not None else None
    # If the host port is random, fall back to the container port for the label
    if sensitive is None and binding.get("container_port") is not None:
        if host_port is None:
            sensitive = SENSITIVE_PORTS.get(int(binding["container_port"]))
    if kind == "loopback":
        level = "SAFE"
        reason = "Bound strictly to loopback %s" % _format_endpoint(binding)
    elif kind == "private":
        level = "LOW"
        reason = "Bound to private/VPN interface %s" % _format_endpoint(binding)
    elif kind == "public":
        # specific public IP (not wildcard)
        if sensitive:
            level = "CRITICAL"
            reason = "Sensitive service (%s) exposed on public address %s" % (
                sensitive,
                _format_endpoint(binding),
            )
        else:
            level = "HIGH"
            reason = "Port exposed on public address %s" % _format_endpoint(binding)
    else:  # wildcard
        endpoint = _format_endpoint(binding)
        if sensitive:
            level = "CRITICAL"
            reason = "Sensitive service (%s) exposed publicly on wildcard %s" % (
                sensitive,
                endpoint,
            )
        else:
            level = "HIGH"
            reason = "Port %s exposed publicly on wildcard %s" % (
                host_port if host_port is not None else "(random host port)",
                binding.get("host_ip") or "0.0.0.0",
            )
            # closer to paid wording when we have a concrete port
            if host_port is not None:
                hip = binding.get("host_ip") or "0.0.0.0"
                reason = "Port %s exposed publicly on wildcard %s" % (host_port, hip)
    binding = dict(binding)
    binding["level"] = level
    binding["reason"] = reason
    binding["sensitive"] = sensitive
    binding["ip_kind"] = kind
    return binding


def _format_endpoint(binding: Dict[str, Any]) -> str:
    ip = binding.get("host_ip") or "0.0.0.0"
    port = binding.get("host_port")
    if port is None:
        return "%s:<ephemeral>" % ip
    if ":" in str(ip) and not str(ip).startswith("["):
        return "%s:%s" % (ip, port)  # paid printed :::8088 for IPv6 unspecified
    return "%s:%s" % (ip, port)


def extract_services(doc: Any) -> Dict[str, Any]:
    if not isinstance(doc, dict):
        raise ComposeError("Compose file root must be a mapping")
    services = doc.get("services")
    if services is None:
        # Compose v1: top-level service names
        skip = {"version", "volumes", "networks", "configs", "secrets", "name", "x-"}
        services = {k: v for k, v in doc.items() if k not in skip and not str(k).startswith("x-") and isinstance(v, dict)}
    if not isinstance(services, dict):
        raise ComposeError("services: must be a mapping")
    return services


def audit_compose(text: str, source: str) -> List[Dict[str, Any]]:
    doc = parse_simple_yaml(text)
    findings: List[Dict[str, Any]] = []
    for name, svc in extract_services(doc).items():
        if not isinstance(svc, dict):
            continue
        ports = svc.get("ports") or []
        if not isinstance(ports, list):
            ports = [ports]
        for entry in ports:
            try:
                bindings = parse_port_entry(entry)
            except ComposeError as exc:
                findings.append(
                    {
                        "service": name,
                        "source": source,
                        "level": "HIGH",
                        "reason": "Could not parse port entry %r: %s" % (entry, exc),
                        "host_ip": None,
                        "host_port": None,
                        "container_port": None,
                        "protocol": None,
                        "sensitive": None,
                        "ip_kind": None,
                        "parse_error": True,
                    }
                )
                continue
            for b in bindings:
                rated = rate_binding(b)
                rated["service"] = name
                rated["source"] = source
                findings.append(rated)
    return findings


def format_report(findings: List[Dict[str, Any]]) -> str:
    lines = [
        "======================================================================",
        " portexpose-lite: Docker Compose published-port report",
        "======================================================================",
    ]
    if not findings:
        lines.append("No published ports found.")
    else:
        width = max(len(str(f.get("service") or "")) for f in findings)
        width = max(width, 8)
        for f in findings:
            endpoint = _format_endpoint(f) if f.get("host_ip") is not None or f.get("host_port") is not None else "-"
            level = (f.get("level") or "?").ljust(8)
            svc = str(f.get("service") or "").ljust(width)
            lines.append("[%s] %s -> %s  | %s" % (level, svc, endpoint, f.get("reason")))
    lines.append("======================================================================")
    return "\n".join(lines)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def default_compose_files() -> List[str]:
    found = []
    for name in DEFAULT_COMPOSE_NAMES:
        if os.path.isfile(name):
            found.append(name)
    return found


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portexpose-lite",
        description=(
            "Read Docker Compose files and flag published ports that bind to "
            "0.0.0.0 / ::, including databases and the Docker API. Read-only."
        ),
    )
    p.add_argument("-V", "--version", action="version", version="portexpose-lite %s" % __version__)
    p.add_argument(
        "-f",
        "--compose-file",
        nargs="+",
        metavar="FILE",
        help="Compose file(s) to audit (default: docker-compose.yml / compose.yaml in the current directory)",
    )
    p.add_argument("--demo", action="store_true", help="Run the built-in sample Compose file and exit")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.demo:
        findings = audit_compose(DEMO_COMPOSE, source="--demo")
        print(format_report(findings))
        print("Read-only: no files or firewall rules were changed.")
        if any(f.get("level") in ("HIGH", "CRITICAL") for f in findings):
            return 1
        return 0
    paths = list(args.compose_file or default_compose_files())
    if not paths:
        print(
            "portexpose-lite: no Compose file given and none of %s found in the current directory"
            % ", ".join(DEFAULT_COMPOSE_NAMES),
            file=sys.stderr,
        )
        return 2
    all_findings: List[Dict[str, Any]] = []
    for path in paths:
        try:
            text = _read(path)
        except OSError as exc:
            print("portexpose-lite: cannot read %s: %s" % (path, exc), file=sys.stderr)
            return 2
        try:
            all_findings.extend(audit_compose(text, source=path))
        except ComposeError as exc:
            print("portexpose-lite: %s: %s" % (path, exc), file=sys.stderr)
            return 2
    print(format_report(all_findings))
    print("Read-only: no files or firewall rules were changed.")
    if any(f.get("level") in ("HIGH", "CRITICAL") for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
