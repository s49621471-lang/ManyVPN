import contextlib
import json
import os
import socket
import subprocess
import tempfile
import time


def singbox_outbound(spec, tag):
    protocol = spec["protocol"]
    out = {"type": protocol, "tag": tag, "server": spec["server"], "server_port": spec["port"]}
    if protocol == "vless":
        out["uuid"] = spec["uuid"]
        out["packet_encoding"] = "xudp"
        if spec.get("flow"):
            out["flow"] = spec["flow"]
    elif protocol == "vmess":
        out["uuid"] = spec["uuid"]
        out["security"] = spec.get("security", "auto")
        out["alter_id"] = spec.get("alter_id", 0)
    elif protocol == "trojan":
        out["password"] = spec["password"]
    elif protocol == "shadowsocks":
        out["method"] = spec["method"]
        out["password"] = spec["password"]
    elif protocol == "hysteria2":
        out["password"] = spec["password"]
        if spec.get("obfs"):
            out["obfs"] = spec["obfs"]
    elif protocol == "tuic":
        out["uuid"] = spec["uuid"]
        out["password"] = spec.get("password", "")
        out["congestion_control"] = spec.get("congestion_control", "bbr")
        out["udp_relay_mode"] = spec.get("udp_relay_mode", "native")
    else:
        return None
    tls = spec.get("tls") or {}
    if tls:
        out["tls"] = json.loads(json.dumps(tls))
    transport = spec.get("transport") or {}
    if transport:
        if transport.get("type") == "xhttp":
            return None
        out["transport"] = json.loads(json.dumps(transport))
    return out


def xray_stream(spec):
    stream = {"network": "raw", "security": "none"}
    transport = spec.get("transport") or {}
    kind = transport.get("type", "tcp")
    if kind in ("tcp", ""):
        stream["network"] = "raw"
    elif kind == "ws":
        stream["network"] = "ws"
        settings = {"path": transport.get("path", "/")}
        host = (transport.get("headers") or {}).get("Host")
        if host:
            settings["host"] = host
        stream["wsSettings"] = settings
    elif kind == "grpc":
        stream["network"] = "grpc"
        stream["grpcSettings"] = {"serviceName": transport.get("service_name", "")}
    elif kind == "http":
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": transport.get("path", "/"), "mode": "stream-one"}
        hosts = transport.get("host") or []
        if hosts:
            stream["xhttpSettings"]["host"] = hosts[0]
    elif kind == "httpupgrade":
        stream["network"] = "httpupgrade"
        stream["httpupgradeSettings"] = {"path": transport.get("path", "/")}
        if transport.get("host"):
            stream["httpupgradeSettings"]["host"] = transport["host"]
    elif kind == "xhttp":
        stream["network"] = "xhttp"
        settings = {"path": transport.get("path", "/"), "mode": transport.get("mode", "auto")}
        if transport.get("host"):
            settings["host"] = transport["host"]
        stream["xhttpSettings"] = settings
    else:
        return None
    tls = spec.get("tls") or {}
    if tls.get("enabled"):
        reality = tls.get("reality") or {}
        fingerprint = (tls.get("utls") or {}).get("fingerprint", "chrome")
        if reality.get("enabled"):
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": tls.get("server_name", ""),
                "fingerprint": fingerprint,
                "publicKey": reality.get("public_key", ""),
                "shortId": reality.get("short_id", ""),
                "spiderX": "/",
            }
        else:
            stream["security"] = "tls"
            settings = {
                "serverName": tls.get("server_name", ""),
                "allowInsecure": bool(tls.get("insecure")),
                "fingerprint": fingerprint,
            }
            if tls.get("alpn"):
                settings["alpn"] = tls["alpn"]
            stream["tlsSettings"] = settings
    return stream


def xray_outbound(spec, tag):
    protocol = spec["protocol"]
    stream = xray_stream(spec)
    if stream is None:
        return None
    if protocol == "vless":
        user = {"id": spec["uuid"], "encryption": "none"}
        if spec.get("flow"):
            user["flow"] = spec["flow"]
        settings = {"vnext": [{"address": spec["server"], "port": spec["port"], "users": [user]}]}
    elif protocol == "vmess":
        user = {"id": spec["uuid"], "alterId": spec.get("alter_id", 0), "security": spec.get("security", "auto")}
        settings = {"vnext": [{"address": spec["server"], "port": spec["port"], "users": [user]}]}
    elif protocol == "trojan":
        settings = {"servers": [{"address": spec["server"], "port": spec["port"], "password": spec["password"]}]}
    elif protocol == "shadowsocks":
        settings = {"servers": [{
            "address": spec["server"], "port": spec["port"],
            "method": spec["method"], "password": spec["password"],
        }]}
    else:
        return None
    return {"tag": tag, "protocol": protocol, "settings": settings, "streamSettings": stream}


def supports(spec, core):
    if core == "sing-box":
        return singbox_outbound(spec, "probe") is not None
    if core == "xray":
        return xray_outbound(spec, "probe") is not None
    return False


def core_for(spec):
    wanted = spec.get("core", "any")
    if wanted == "xray":
        return "xray" if supports(spec, "xray") else ""
    if wanted == "sing-box":
        return "sing-box" if supports(spec, "sing-box") else ""
    if supports(spec, "sing-box"):
        return "sing-box"
    if supports(spec, "xray"):
        return "xray"
    return ""


def build_singbox(items, base_port):
    inbounds = []
    outbounds = []
    rules = []
    for index, spec in enumerate(items):
        tag = f"out-{index}"
        inbound_tag = f"in-{index}"
        inbounds.append({
            "type": "mixed", "tag": inbound_tag,
            "listen": "127.0.0.1", "listen_port": base_port + index,
        })
        outbounds.append(singbox_outbound(spec, tag))
        rules.append({"inbound": [inbound_tag], "outbound": tag})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"disabled": True, "level": "fatal"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct", "auto_detect_interface": False},
    }


def build_xray(items, base_port):
    inbounds = []
    outbounds = []
    rules = []
    for index, spec in enumerate(items):
        tag = f"out-{index}"
        inbound_tag = f"in-{index}"
        inbounds.append({
            "tag": inbound_tag, "listen": "127.0.0.1", "port": base_port + index,
            "protocol": "http", "settings": {},
        })
        outbounds.append(xray_outbound(spec, tag))
        rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": tag})
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    return {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def _listening(port):
    with contextlib.closing(socket.socket()) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_ready(base_port, count, timeout):
    deadline = time.monotonic() + timeout
    targets = list(range(base_port, base_port + count))
    while time.monotonic() < deadline:
        pending = [port for port in targets if not _listening(port)]
        if not pending:
            return True
        targets = pending
        time.sleep(0.4)
    return len(targets) < count


@contextlib.contextmanager
def running(binary, config, base_port, count, timeout):
    directory = tempfile.mkdtemp(prefix="manyvpn-")
    path = os.path.join(directory, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False)
    process = subprocess.Popen(
        [binary, "run", "-c", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=directory, start_new_session=True,
    )
    try:
        ready = wait_ready(base_port, count, timeout)
        yield process if ready else None
    finally:
        with contextlib.suppress(ProcessLookupError, OSError):
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=6)
        with contextlib.suppress(OSError):
            os.remove(path)
            os.rmdir(directory)
