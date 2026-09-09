from urllib.parse import quote

from . import parse
from .model import Node

SUPPORTED = {"vless", "vmess", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic"}


def _bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _transport(item):
    network = str(item.get("network", "tcp") or "tcp").lower()
    if network in ("tcp", "raw", ""):
        return {}
    if network == "ws":
        opts = item.get("ws-opts") or {}
        spec = {"type": "ws", "path": str(opts.get("path", "/") or "/")}
        headers = opts.get("headers") or {}
        host = headers.get("Host") or headers.get("host") or item.get("ws-headers", {}).get("Host")
        if host:
            spec["headers"] = {"Host": str(host)}
        return spec
    if network == "grpc":
        opts = item.get("grpc-opts") or {}
        return {"type": "grpc", "service_name": str(opts.get("grpc-service-name", "") or "")}
    if network in ("h2", "http"):
        opts = item.get("h2-opts") or item.get("http-opts") or {}
        spec = {"type": "http", "path": str(opts.get("path", "/") or "/")}
        host = opts.get("host")
        if isinstance(host, list) and host:
            spec["host"] = [str(entry) for entry in host]
        elif host:
            spec["host"] = [str(host)]
        return spec
    return None


def _tls(item, server):
    if not (_bool(item.get("tls")) or item.get("reality-opts")):
        return {}
    sni = item.get("servername") or item.get("sni") or item.get("peer") or ""
    tls = {"enabled": True, "insecure": _bool(item.get("skip-cert-verify"))}
    if sni:
        tls["server_name"] = str(sni)
    elif not parse._is_ip(server):
        tls["server_name"] = server
    alpn = item.get("alpn")
    if isinstance(alpn, list):
        picked = [str(entry) for entry in alpn if str(entry) in ("h2", "http/1.1", "h3")]
        if picked:
            tls["alpn"] = picked
    tls["utls"] = {"enabled": True, "fingerprint": parse._fingerprint(str(item.get("client-fingerprint", "")))}
    reality = item.get("reality-opts") or {}
    if reality.get("public-key"):
        tls["reality"] = {"enabled": True, "public_key": str(reality["public-key"])}
        if reality.get("short-id") is not None:
            tls["reality"]["short_id"] = str(reality["short-id"])
        tls["insecure"] = False
    return tls


def _uri(spec, name):
    protocol = spec["protocol"]
    server = spec["server"]
    port = spec["port"]
    tls = spec.get("tls") or {}
    transport = spec.get("transport") or {}
    tag = quote(name, safe="")
    query = []
    if protocol == "shadowsocks":
        import base64
        userinfo = base64.urlsafe_b64encode(f"{spec['method']}:{spec['password']}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{tag}"
    if tls.get("reality"):
        query.append("security=reality")
        query.append("pbk=" + quote(tls["reality"]["public_key"], safe=""))
        if tls["reality"].get("short_id"):
            query.append("sid=" + quote(tls["reality"]["short_id"], safe=""))
    elif tls.get("enabled"):
        query.append("security=tls")
    else:
        query.append("security=none")
    if tls.get("server_name"):
        query.append("sni=" + quote(tls["server_name"], safe=""))
    if tls.get("insecure"):
        query.append("allowInsecure=1")
    if tls.get("utls"):
        query.append("fp=" + tls["utls"]["fingerprint"])
    network = transport.get("type", "tcp") or "tcp"
    query.append("type=" + network)
    if network == "ws":
        query.append("path=" + quote(transport.get("path", "/"), safe=""))
        host = (transport.get("headers") or {}).get("Host")
        if host:
            query.append("host=" + quote(host, safe=""))
    elif network == "grpc":
        query.append("serviceName=" + quote(transport.get("service_name", ""), safe=""))
    elif network == "http":
        query.append("path=" + quote(transport.get("path", "/"), safe=""))
        hosts = transport.get("host") or []
        if hosts:
            query.append("host=" + quote(",".join(hosts), safe=""))
    if protocol == "vless":
        if spec.get("flow"):
            query.append("flow=" + spec["flow"])
        query.append("encryption=none")
        return f"vless://{spec['uuid']}@{server}:{port}?" + "&".join(query) + f"#{tag}"
    if protocol == "trojan":
        return f"trojan://{quote(spec['password'], safe='')}@{server}:{port}?" + "&".join(query) + f"#{tag}"
    if protocol == "vmess":
        import base64
        import json
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port), "id": spec["uuid"],
            "aid": str(spec.get("alter_id", 0)), "scy": spec.get("security", "auto"),
            "net": network, "type": "none",
            "host": (transport.get("headers") or {}).get("Host", "") or ",".join(transport.get("host") or []),
            "path": transport.get("path", "") or transport.get("service_name", ""),
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        blob = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
        return "vmess://" + blob
    if protocol == "hysteria2":
        return f"hysteria2://{quote(spec['password'], safe='')}@{server}:{port}?" + "&".join(query) + f"#{tag}"
    return ""


def convert(item, source="", whitelist=False):
    kind = str(item.get("type", "")).lower()
    if kind not in SUPPORTED:
        return None
    server = parse._clean_host(str(item.get("server", "")))
    port = parse._valid_port(item.get("port"))
    if not parse._valid_host(server) or not port:
        return None
    name = str(item.get("name", "") or "")
    transport = _transport(item)
    if transport is None:
        return None
    if kind == "vless":
        uuid = str(item.get("uuid", "") or "")
        if not uuid:
            return None
        spec = {"protocol": "vless", "server": server, "port": port, "uuid": uuid}
        flow = str(item.get("flow", "") or "")
        if flow:
            if flow != "xtls-rprx-vision":
                return None
            spec["flow"] = flow
    elif kind == "vmess":
        uuid = str(item.get("uuid", "") or "")
        if not uuid:
            return None
        cipher = str(item.get("cipher", "auto") or "auto").lower()
        spec = {
            "protocol": "vmess", "server": server, "port": port, "uuid": uuid,
            "alter_id": int(item.get("alterId", 0) or 0),
            "security": cipher if cipher in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero") else "auto",
        }
    elif kind == "trojan":
        password = str(item.get("password", "") or "")
        if not password:
            return None
        spec = {"protocol": "trojan", "server": server, "port": port, "password": password}
    elif kind in ("ss", "shadowsocks"):
        if item.get("plugin"):
            return None
        method = str(item.get("cipher", "") or "").lower()
        if method not in parse.SS_METHODS:
            return None
        spec = {
            "protocol": "shadowsocks", "server": server, "port": port,
            "method": method, "password": str(item.get("password", "") or ""),
        }
    elif kind in ("hysteria2", "hy2"):
        password = str(item.get("password", "") or "")
        if not password:
            return None
        spec = {"protocol": "hysteria2", "server": server, "port": port, "password": password}
    else:
        return None
    if kind not in ("ss", "shadowsocks"):
        tls = _tls(item, server)
        if kind in ("trojan", "hysteria2", "hy2") and not tls:
            tls = {"enabled": True, "insecure": _bool(item.get("skip-cert-verify"))}
            if not parse._is_ip(server):
                tls["server_name"] = server
        if tls:
            spec["tls"] = tls
        if transport:
            spec["transport"] = transport
    uri = _uri(spec, name or f"{server}:{port}")
    if not uri:
        return None
    return Node(
        uri=uri, protocol=spec["protocol"], server=server, port=port, spec=spec,
        key=parse.fingerprint(spec), source=source, remark=name, whitelist=whitelist,
    )


def extract(items, source="", whitelist=False):
    nodes = []
    for item in items:
        try:
            node = convert(item, source, whitelist)
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        if node is not None:
            nodes.append(node)
    return nodes
