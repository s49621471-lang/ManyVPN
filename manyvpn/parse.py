import base64
import binascii
import ipaddress
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .model import Node

SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://",
    "hysteria2://", "hy2://", "tuic://",
)

SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "chacha20-ietf", "rc4-md5", "none",
}

TRANSPORTS = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "raw", "xhttp", "splithttp"}

XRAY_ONLY = {"xhttp"}

FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq",
    "ios", "android", "random", "randomized",
}

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def b64decode(text):
    data = re.sub(r"\s+", "", text)
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def _first(params, *keys, default=""):
    for key in keys:
        value = params.get(key)
        if value:
            item = value[0] if isinstance(value, list) else value
            if item not in (None, ""):
                return str(item)
    return default


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _clean_host(host):
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.strip().rstrip(".").lower()


def _valid_host(host):
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not re.match(r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$", host):
        return False
    return "." in host


def _valid_port(port):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def _fingerprint(value):
    value = (value or "").strip().lower()
    if value in FINGERPRINTS:
        return "randomized" if value == "random" else value
    return "chrome"


def _alpn(value):
    if not value:
        return []
    items = [item.strip() for item in unquote(value).split(",")]
    return [item for item in items if item in ("h2", "http/1.1", "h3")]


def _transport(params, network, default_host=""):
    network = (network or "tcp").strip().lower()
    if network in ("h2", "http"):
        network = "http"
    if network == "raw":
        network = "tcp"
    if network == "splithttp":
        network = "xhttp"
    if network not in TRANSPORTS:
        return None
    path = unquote(_first(params, "path", default="/")) or "/"
    host = _first(params, "host", "Host", default=default_host)
    if network == "ws":
        spec = {"type": "ws", "path": path}
        if host:
            spec["headers"] = {"Host": host}
        early = _first(params, "ed", "eh")
        if early:
            spec["early_data_header_name"] = "Sec-WebSocket-Protocol"
            try:
                spec["max_early_data"] = int(early)
            except ValueError:
                spec["max_early_data"] = 2048
        return spec
    if network == "grpc":
        service = _first(params, "serviceName", "servicename", "path", default="")
        return {"type": "grpc", "service_name": unquote(service)}
    if network == "http":
        spec = {"type": "http", "path": path}
        if host:
            spec["host"] = [item for item in host.split(",") if item]
        return spec
    if network == "xhttp":
        spec = {"type": "xhttp", "path": path, "mode": _first(params, "mode", default="auto")}
        if host:
            spec["host"] = host
        extra = _first(params, "extra")
        if extra:
            spec["extra"] = unquote(extra)
        return spec
    if network == "httpupgrade":
        spec = {"type": "httpupgrade", "path": path}
        if host:
            spec["host"] = host
        return spec
    header = _first(params, "headerType", "type", default="none").lower()
    if header == "http":
        spec = {"type": "http", "path": path}
        if host:
            spec["host"] = [item for item in host.split(",") if item]
        return spec
    return {}


def _tls(params, security, default_sni, server):
    security = (security or "").strip().lower()
    if security in ("", "none"):
        return {}
    sni = _first(params, "sni", "peer", "servername", default=default_sni)
    sni = unquote(sni) or (server if not _is_ip(server) else "")
    tls = {"enabled": True, "insecure": _truthy(_first(params, "allowInsecure", "insecure", "skip-cert-verify"))}
    if sni:
        tls["server_name"] = sni
    alpn = _alpn(_first(params, "alpn"))
    if alpn:
        tls["alpn"] = alpn
    tls["utls"] = {"enabled": True, "fingerprint": _fingerprint(_first(params, "fp", "fingerprint"))}
    if security == "reality":
        pbk = _first(params, "pbk", "publicKey", "public-key")
        if not pbk:
            return {}
        tls["reality"] = {"enabled": True, "public_key": pbk}
        sid = _first(params, "sid", "shortId", "short-id")
        if sid:
            tls["reality"]["short_id"] = sid
        tls["insecure"] = False
    return tls


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_vless(uri):
    parts = urlsplit(uri)
    uuid = unquote(parts.username or "")
    if not uuid:
        return None
    host = _clean_host(parts.hostname)
    port = _valid_port(parts.port)
    if not _valid_host(host) or not port:
        return None
    params = parse_qs(parts.query)
    security = _first(params, "security", default="none")
    transport = _transport(params, _first(params, "type", "net", default="tcp"))
    if transport is None:
        return None
    spec = {"protocol": "vless", "server": host, "port": port, "uuid": uuid}
    encryption = _first(params, "encryption", default="none")
    if encryption not in ("", "none"):
        return None
    tls = _tls(params, security, "", host)
    if tls:
        spec["tls"] = tls
    flow = _first(params, "flow")
    if flow:
        if flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            return None
        spec["flow"] = "xtls-rprx-vision"
    if transport:
        spec["transport"] = transport
        if transport.get("type") in XRAY_ONLY:
            spec["core"] = "xray"
    return spec, unquote(parts.fragment)


def parse_vmess(uri):
    body = uri[len("vmess://"):]
    text = b64decode(body)
    if not text.strip().startswith("{"):
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    host = _clean_host(str(data.get("add", "")))
    port = _valid_port(data.get("port"))
    uuid = str(data.get("id", "")).strip()
    if not _valid_host(host) or not port or not uuid:
        return None
    params = {
        "path": [str(data.get("path", "/") or "/")],
        "host": [str(data.get("host", "") or "")],
        "serviceName": [str(data.get("path", "") or "")],
        "headerType": [str(data.get("type", "none") or "none")],
        "alpn": [str(data.get("alpn", "") or "")],
        "fp": [str(data.get("fp", "") or "")],
        "sni": [str(data.get("sni", "") or "")],
    }
    network = str(data.get("net", "tcp") or "tcp")
    transport = _transport(params, network)
    if transport is None:
        return None
    security = str(data.get("tls", "") or "")
    spec = {"protocol": "vmess", "server": host, "port": port, "uuid": uuid}
    cipher = str(data.get("scy", "auto") or "auto").lower()
    spec["security"] = cipher if cipher in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero") else "auto"
    try:
        spec["alter_id"] = int(data.get("aid", 0) or 0)
    except (TypeError, ValueError):
        spec["alter_id"] = 0
    tls = _tls(params, "tls" if security in ("tls", "reality") else "", str(data.get("sni", "") or ""), host)
    if tls:
        spec["tls"] = tls
    if transport:
        spec["transport"] = transport
        if transport.get("type") in XRAY_ONLY:
            spec["core"] = "xray"
    return spec, str(data.get("ps", "") or "")


def parse_trojan(uri):
    parts = urlsplit(uri)
    password = unquote(parts.username or "")
    if not password:
        return None
    host = _clean_host(parts.hostname)
    port = _valid_port(parts.port)
    if not _valid_host(host) or not port:
        return None
    params = parse_qs(parts.query)
    transport = _transport(params, _first(params, "type", "net", default="tcp"))
    if transport is None:
        return None
    spec = {"protocol": "trojan", "server": host, "port": port, "password": password}
    tls = _tls(params, _first(params, "security", default="tls"), "", host)
    spec["tls"] = tls or {"enabled": True, "insecure": False, "server_name": host}
    if transport:
        spec["transport"] = transport
        if transport.get("type") in XRAY_ONLY:
            spec["core"] = "xray"
    return spec, unquote(parts.fragment)


def parse_ss(uri):
    body = uri[len("ss://"):]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
        fragment = unquote(fragment)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    if "@" not in body:
        decoded = b64decode(body)
        if "@" not in decoded:
            return None
        body = decoded
    userinfo, _, hostpart = body.rpartition("@")
    if ":" not in userinfo:
        decoded = b64decode(userinfo)
        if ":" not in decoded:
            return None
        userinfo = decoded
    method, _, password = userinfo.partition(":")
    method = method.strip().lower()
    if method not in SS_METHODS:
        return None
    if hostpart.startswith("["):
        host, _, port = hostpart[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = hostpart.rpartition(":")
    host = _clean_host(host)
    port = _valid_port(port)
    if not _valid_host(host) or not port:
        return None
    if query:
        params = parse_qs(query)
        if _first(params, "plugin"):
            return None
    return {
        "protocol": "shadowsocks", "server": host, "port": port,
        "method": method, "password": unquote(password),
    }, fragment


def parse_hysteria2(uri):
    parts = urlsplit(uri)
    host = _clean_host(parts.hostname)
    port = _valid_port(parts.port)
    if not _valid_host(host) or not port:
        return None
    password = unquote(parts.username or "")
    if parts.password:
        password = f"{password}:{unquote(parts.password)}"
    if not password:
        return None
    params = parse_qs(parts.query)
    sni = unquote(_first(params, "sni", "peer", default=""))
    spec = {
        "protocol": "hysteria2", "core": "sing-box", "server": host, "port": port, "password": password,
        "tls": {
            "enabled": True,
            "insecure": _truthy(_first(params, "insecure", "allowInsecure")),
        },
    }
    if sni:
        spec["tls"]["server_name"] = sni
    elif not _is_ip(host):
        spec["tls"]["server_name"] = host
    alpn = _alpn(_first(params, "alpn"))
    if alpn:
        spec["tls"]["alpn"] = alpn
    obfs = _first(params, "obfs")
    obfs_pass = _first(params, "obfs-password", "obfsParam")
    if obfs == "salamander" and obfs_pass:
        spec["obfs"] = {"type": "salamander", "password": obfs_pass}
    return spec, unquote(parts.fragment)


def parse_tuic(uri):
    parts = urlsplit(uri)
    host = _clean_host(parts.hostname)
    port = _valid_port(parts.port)
    uuid = unquote(parts.username or "")
    password = unquote(parts.password or "")
    if not _valid_host(host) or not port or not uuid:
        return None
    params = parse_qs(parts.query)
    spec = {
        "protocol": "tuic", "core": "sing-box", "server": host, "port": port,
        "uuid": uuid, "password": password,
        "congestion_control": _first(params, "congestion_control", default="bbr"),
        "udp_relay_mode": _first(params, "udp_relay_mode", default="native"),
        "tls": {
            "enabled": True,
            "insecure": _truthy(_first(params, "allow_insecure", "insecure")),
        },
    }
    sni = unquote(_first(params, "sni", default=""))
    if sni:
        spec["tls"]["server_name"] = sni
    elif not _is_ip(host):
        spec["tls"]["server_name"] = host
    alpn = _alpn(_first(params, "alpn"))
    if alpn:
        spec["tls"]["alpn"] = alpn
    return spec, unquote(parts.fragment)


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
}


def fingerprint(spec):
    tls = spec.get("tls") or {}
    reality = tls.get("reality") or {}
    transport = spec.get("transport") or {}
    parts = [
        spec.get("protocol", ""),
        spec.get("server", ""),
        str(spec.get("port", "")),
        spec.get("uuid", "") or spec.get("password", ""),
        spec.get("method", ""),
        transport.get("type", ""),
        transport.get("path", "") or transport.get("service_name", ""),
        tls.get("server_name", ""),
        reality.get("public_key", ""),
    ]
    return "|".join(parts)


def parse(uri, source="", whitelist=False):
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    handler = PARSERS.get(scheme)
    if handler is None:
        return None
    if scheme == "hy2":
        uri = "hysteria2://" + uri.split("://", 1)[1]
    try:
        parsed = handler(uri)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError):
        return None
    if not parsed:
        return None
    spec, remark = parsed
    return Node(
        uri=uri,
        protocol=spec["protocol"],
        server=spec["server"],
        port=spec["port"],
        spec=spec,
        key=fingerprint(spec),
        source=source,
        remark=remark or "",
        whitelist=whitelist,
    )


def extract(text, source="", whitelist=False):
    nodes = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or not line.lower().startswith(SCHEMES):
            continue
        node = parse(line, source, whitelist)
        if node is not None:
            nodes.append(node)
    return nodes
