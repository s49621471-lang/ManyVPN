import base64
import json
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import quote

from . import countries

AUTO = "⚡ Авто выбор"
AUTO_WHITE = "⚡ Авто выбор 🏳️"
WHITE_MARK = "🏳️"


def _label(code, whitelist):
    base = f"{countries.flag(code)} {countries.name(code)}"
    return f"{base} {WHITE_MARK}" if whitelist else base


def assign_names(nodes):
    grouped = defaultdict(list)
    for node in nodes:
        grouped[(countries.normalize(node.country), node.whitelist)].append(node)
    names = {}
    for (code, whitelist), items in grouped.items():
        base = _label(code, whitelist)
        if len(items) == 1:
            names[id(items[0])] = base
            continue
        for index, node in enumerate(items, start=1):
            names[id(node)] = f"{base} {index}"
    return names


def retag(node, name):
    if node.protocol == "vmess":
        body = node.uri[len("vmess://"):]
        padded = body.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            data = json.loads(base64.b64decode(padded).decode("utf-8", "ignore"))
        except (ValueError, TypeError):
            return node.uri
        data["ps"] = name
        blob = base64.b64encode(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return "vmess://" + blob
    base = node.uri.split("#", 1)[0]
    return f"{base}#{quote(name, safe='')}"


def uri_list(normal, white):
    names = assign_names(normal + white)
    lines = []
    if normal:
        lines.append(retag(normal[0], AUTO))
    for node in normal:
        lines.append(retag(node, names[id(node)]))
    if white:
        lines.append(retag(white[0], AUTO_WHITE))
    for node in white:
        lines.append(retag(node, names[id(node)]))
    return lines


def plain(normal, white):
    return "\n".join(uri_list(normal, white)) + "\n"


def encoded(normal, white):
    payload = "\n".join(uri_list(normal, white))
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def _singbox_supported(node):
    from . import cores
    return cores.singbox_outbound(node.spec, "check") is not None


def singbox(normal, white, title="ManyVPN"):
    from . import cores

    usable_normal = [node for node in normal if _singbox_supported(node)]
    usable_white = [node for node in white if _singbox_supported(node)]
    names = assign_names(usable_normal + usable_white)

    outbounds = []
    normal_tags = []
    white_tags = []
    for node in usable_normal:
        tag = names[id(node)]
        outbounds.append(cores.singbox_outbound(node.spec, tag))
        normal_tags.append(tag)
    for node in usable_white:
        tag = names[id(node)]
        outbounds.append(cores.singbox_outbound(node.spec, tag))
        white_tags.append(tag)

    groups = []
    selector = []
    if normal_tags:
        groups.append({
            "type": "urltest", "tag": AUTO, "outbounds": normal_tags,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "5m", "tolerance": 50, "idle_timeout": "30m",
        })
        selector.append(AUTO)
    selector.extend(normal_tags)
    if white_tags:
        groups.append({
            "type": "urltest", "tag": AUTO_WHITE, "outbounds": white_tags,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "5m", "tolerance": 50, "idle_timeout": "30m",
        })
        selector.append(AUTO_WHITE)
    selector.extend(white_tags)
    if not selector:
        selector = ["direct"]

    head = {
        "type": "selector", "tag": title, "outbounds": selector,
        "default": selector[0], "interrupt_exist_connections": False,
    }

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": title},
                {"tag": "local", "address": "local", "detour": "direct"},
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tun", "tag": "tun-in", "interface_name": "ManyVPN",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "mtu": 9000, "auto_route": True, "strict_route": True,
                "stack": "mixed", "sniff": True, "sniff_override_destination": False,
            },
            {
                "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                "listen_port": 2080, "sniff": True,
            },
        ],
        "outbounds": [head] + groups + outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"ip_is_private": True, "outbound": "direct"}],
            "final": title,
            "auto_detect_interface": True,
        },
        "experimental": {
            "clash_api": {"external_controller": "127.0.0.1:9090", "default_mode": "rule"},
            "cache_file": {"enabled": True, "store_fakeip": False},
        },
    }
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"


CLASH_TRANSPORTS = {"tcp", "ws", "grpc"}


def _clash_proxy(node, name):
    spec = node.spec
    transport = spec.get("transport") or {}
    kind = transport.get("type", "tcp") or "tcp"
    if kind not in CLASH_TRANSPORTS:
        return None
    tls = spec.get("tls") or {}
    proxy = {"name": name, "server": spec["server"], "port": spec["port"], "udp": True}
    protocol = spec["protocol"]
    if protocol == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = spec["uuid"]
        if spec.get("flow"):
            proxy["flow"] = spec["flow"]
    elif protocol == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = spec["uuid"]
        proxy["alterId"] = spec.get("alter_id", 0)
        proxy["cipher"] = spec.get("security", "auto")
    elif protocol == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = spec["password"]
    elif protocol == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = spec["method"]
        proxy["password"] = spec["password"]
        return proxy
    elif protocol == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = spec["password"]
        if tls.get("server_name"):
            proxy["sni"] = tls["server_name"]
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if spec.get("obfs"):
            proxy["obfs"] = spec["obfs"]["type"]
            proxy["obfs-password"] = spec["obfs"]["password"]
        return proxy
    elif protocol == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = spec["uuid"]
        proxy["password"] = spec.get("password", "")
        proxy["congestion-controller"] = spec.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = spec.get("udp_relay_mode", "native")
        if tls.get("server_name"):
            proxy["sni"] = tls["server_name"]
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        return proxy
    else:
        return None

    if tls.get("enabled"):
        if protocol == "trojan":
            if tls.get("server_name"):
                proxy["sni"] = tls["server_name"]
        else:
            proxy["tls"] = True
            if tls.get("server_name"):
                proxy["servername"] = tls["server_name"]
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["client-fingerprint"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
        reality = tls.get("reality") or {}
        if reality.get("enabled"):
            proxy["reality-opts"] = {"public-key": reality["public_key"]}
            if reality.get("short_id"):
                proxy["reality-opts"]["short-id"] = reality["short_id"]
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif protocol == "trojan":
        return None

    proxy["network"] = kind
    if kind == "ws":
        options = {"path": transport.get("path", "/")}
        host = (transport.get("headers") or {}).get("Host")
        if host:
            options["headers"] = {"Host": host}
        proxy["ws-opts"] = options
    elif kind == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    return proxy


def clash(normal, white, title="ManyVPN"):
    import yaml

    names = assign_names(normal + white)
    proxies = []
    normal_names = []
    white_names = []
    for node in normal:
        proxy = _clash_proxy(node, names[id(node)])
        if proxy:
            proxies.append(proxy)
            normal_names.append(proxy["name"])
    for node in white:
        proxy = _clash_proxy(node, names[id(node)])
        if proxy:
            proxies.append(proxy)
            white_names.append(proxy["name"])

    seen = set()
    unique = []
    for proxy in proxies:
        if proxy["name"] in seen:
            continue
        seen.add(proxy["name"])
        unique.append(proxy)
    proxies = unique
    normal_names = [name for name in normal_names if name in seen]
    white_names = [name for name in white_names if name in seen]

    groups = []
    selector = []
    if normal_names:
        groups.append({
            "name": AUTO, "type": "url-test", "proxies": normal_names,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300, "tolerance": 50, "lazy": True,
        })
        selector.append(AUTO)
    selector.extend(normal_names)
    if white_names:
        groups.append({
            "name": AUTO_WHITE, "type": "url-test", "proxies": white_names,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300, "tolerance": 50, "lazy": True,
        })
        selector.append(AUTO_WHITE)
    selector.extend(white_names)
    if not selector:
        selector = ["DIRECT"]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": title, "type": "select", "proxies": selector}
        ] + groups,
        "rules": ["GEOIP,PRIVATE,DIRECT,no-resolve", f"MATCH,{title}"],
    }
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=4096)


def status(normal, white, stats, sources, title="ManyVPN"):
    names = assign_names(normal + white)
    by_country = defaultdict(list)
    for node in normal + white:
        by_country[countries.normalize(node.country)].append(node)
    data = {
        "name": title,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(normal) + len(white),
        "normal": len(normal),
        "whitelist": len(white),
        "countries": len(by_country),
        "stats": stats,
        "sources": sources,
        "servers": [
            {
                "name": names[id(node)],
                "country": node.country,
                "latency_ms": round(node.latency, 1),
                "protocol": node.protocol,
                "transport": (node.spec.get("transport") or {}).get("type", "tcp"),
                "whitelist": node.whitelist,
                "exit_ip": node.exit_ip,
            }
            for node in normal + white
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def summary(normal, white, stats, repo, branch="sub", title="ManyVPN"):
    names = assign_names(normal + white)
    by_country = defaultdict(list)
    for node in normal:
        by_country[countries.normalize(node.country)].append(node)
    white_countries = defaultdict(list)
    for node in white:
        white_countries[countries.normalize(node.country)].append(node)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    base_raw = f"https://raw.githubusercontent.com/{repo}/{branch}"
    base_cdn = f"https://cdn.jsdelivr.net/gh/{repo}@{branch}"
    lines = [
        f"# {title}",
        "",
        f"Обновлено: **{stamp}**",
        "",
        f"Серверов: **{len(normal) + len(white)}** "
        f"(обычных {len(normal)}, с обходом белых списков {len(white)}) · "
        f"стран: **{len(by_country) + len(white_countries)}**",
        "",
        "## Ссылка на подписку",
        "",
        "```",
        f"{base_raw}/manyvpn.txt",
        "```",
        "",
        "Зеркало (CDN, если raw.githubusercontent недоступен):",
        "",
        "```",
        f"{base_cdn}/manyvpn.txt",
        "```",
        "",
        "| Формат | Ссылка |",
        "| --- | --- |",
        f"| base64 (v2rayNG, Happ, Streisand, Shadowrocket, NekoBox) | `{base_raw}/manyvpn.txt` |",
        f"| обычный список URI | `{base_raw}/manyvpn-plain.txt` |",
        f"| sing-box (Hiddify, Happ, NekoBox, Karing) | `{base_raw}/manyvpn-singbox.json` |",
        f"| Clash / Mihomo | `{base_raw}/manyvpn-clash.yaml` |",
        f"| статус и статистика | `{base_raw}/status.json` |",
        "",
        "## Страны",
        "",
        "| Страна | Серверов | Лучший пинг |",
        "| --- | ---: | ---: |",
    ]
    order = sorted(by_country.keys(), key=lambda code: by_country[code][0].latency)
    for code in order:
        items = by_country[code]
        best = min(node.latency for node in items)
        lines.append(f"| {countries.flag(code)} {countries.name(code)} | {len(items)} | {best:.0f} ms |")
    if white_countries:
        lines += [
            "",
            "## Обход белых списков",
            "",
            "| Страна | Серверов | Лучший пинг |",
            "| --- | ---: | ---: |",
        ]
        order = sorted(white_countries.keys(), key=lambda code: white_countries[code][0].latency)
        for code in order:
            items = white_countries[code]
            best = min(node.latency for node in items)
            lines.append(
                f"| {countries.flag(code)} {countries.name(code)} {WHITE_MARK} | {len(items)} | {best:.0f} ms |"
            )
    lines += [
        "",
        "## Проверка",
        "",
        f"- получено конфигов: {stats.get('fetched', 0)}",
        f"- источников ответило: {stats.get('sources_ok', 0)} из {stats.get('sources_total', 0)}",
        f"- отправлено на глубокую проверку: {stats.get('candidates', 0)}",
        f"- прошло проверку страны и скорости: {stats.get('verified', 0)}",
        f"- время сборки: {stats.get('duration_sec', 0)} с",
        "",
        "Страна каждого сервера определяется реальным выходным IP: трафик пропускается "
        "через сервер и проверяется адрес выхода, а не название конфига.",
        "",
    ]
    return "\n".join(lines)
