import random
from collections import defaultdict

from . import countries, hints, state

PROTOCOL_RANK = {
    "vless": 0, "trojan": 1, "hysteria2": 2, "vmess": 3, "tuic": 4, "shadowsocks": 5,
}

XRAY_PENALTY = 1.05


def dedupe(nodes, max_per_endpoint):
    seen = set()
    per_endpoint = defaultdict(int)
    result = []
    for node in nodes:
        if node.key in seen:
            continue
        endpoint = node.endpoint()
        if per_endpoint[endpoint] >= max_per_endpoint:
            continue
        seen.add(node.key)
        per_endpoint[endpoint] += 1
        result.append(node)
    return result


def _quality(node, history):
    tls = node.spec.get("tls") or {}
    rank = PROTOCOL_RANK.get(node.protocol, 6)
    if node.protocol == "vless" and (tls.get("reality") or {}).get("enabled"):
        rank = -1
    return (
        -state.reliability(history, node.key),
        rank,
        node.latency or 9999.0,
    )


def prioritize(nodes, limit, history):
    groups = defaultdict(list)
    for node in nodes:
        node.hint = hints.guess(node.remark) or hints.guess(node.source)
        groups[node.hint].append(node)
    for items in groups.values():
        items.sort(key=lambda node: _quality(node, history))
    order = sorted(groups.keys(), key=lambda code: (code == "", -len(groups[code])))
    ordered = []
    index = 0
    while len(ordered) < len(nodes):
        added = False
        for code in order:
            items = groups[code]
            if index < len(items):
                ordered.append(items[index])
                added = True
        if not added:
            break
        index += 1
    if limit and len(ordered) > limit:
        ordered = ordered[:limit]
    random.Random(0).shuffle(ordered)
    return ordered


def _score(node, history):
    factor = 1.15 - 0.3 * state.reliability(history, node.key)
    if node.spec.get("core") == "xray":
        factor *= XRAY_PENALTY
    return node.latency * factor


def _pick_country(items, limit):
    chosen = []
    taken = set()
    used = defaultdict(int)
    for allowance in (1, 2, 3):
        for node in items:
            if len(chosen) >= limit:
                return chosen
            if id(node) in taken:
                continue
            marker = node.exit_ip or node.endpoint()
            if used[marker] >= allowance:
                continue
            used[marker] += 1
            taken.add(id(node))
            chosen.append(node)
    return chosen


def _group(nodes, config, history):
    excluded = {countries.normalize(code) for code in config.get("exclude_countries", [])}
    buckets = defaultdict(list)
    for node in nodes:
        code = countries.normalize(node.country)
        if not code or code in excluded or not countries.known(code):
            continue
        if node.latency > config["latency_max_ms"]:
            continue
        buckets[code].append(node)
    picked = {}
    for code, items in buckets.items():
        items.sort(key=lambda node: _score(node, history))
        selected = _pick_country(items, config["max_per_country"])
        if selected:
            picked[code] = selected
    return picked


def _order(picked, mode):
    if mode == "alpha":
        return sorted(picked.keys(), key=lambda code: countries.name(code))
    return sorted(picked.keys(), key=lambda code: picked[code][0].latency)


def choose(nodes, config, history):
    normal_nodes = [node for node in nodes if not node.whitelist]
    white_nodes = [node for node in nodes if node.whitelist]
    normal = _group(normal_nodes, config, history)
    white = _group(white_nodes, config, history)
    mode = config.get("country_order", "latency")

    total = int(config["max_total"])
    share = float(config.get("whitelist_share", 0.25))
    white_flat = [node for code in _order(white, mode) for node in white[code]]
    normal_flat = [node for code in _order(normal, mode) for node in normal[code]]
    white_cap = min(len(white_flat), max(int(config.get("min_whitelist", 0)), int(total * share)))
    normal_cap = total - white_cap
    if len(normal_flat) < normal_cap:
        white_cap = min(len(white_flat), total - len(normal_flat))
    normal_flat = normal_flat[:max(0, normal_cap)]
    white_flat = white_flat[:max(0, white_cap)]

    stats = {
        "countries_normal": len({node.country for node in normal_flat}),
        "countries_whitelist": len({node.country for node in white_flat}),
        "selected_normal": len(normal_flat),
        "selected_whitelist": len(white_flat),
    }
    return normal_flat, white_flat, stats
