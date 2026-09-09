import asyncio
import json
import ssl
import time

import aiohttp

from . import cores, countries

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _parse_trace(text):
    country = ""
    address = ""
    for line in text.splitlines():
        if line.startswith("loc="):
            country = line[4:].strip()
        elif line.startswith("ip="):
            address = line[3:].strip()
    return countries.normalize(country), address


def _parse_ipapi(text):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return "", ""
    if data.get("status") not in (None, "success"):
        return "", ""
    return countries.normalize(str(data.get("countryCode", ""))), str(data.get("query", ""))


PARSERS = {"trace": _parse_trace, "ipapi": _parse_ipapi}


async def _fetch(session, url, proxy, timeout):
    start = time.monotonic()
    async with session.get(
        url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False
    ) as response:
        if response.status != 200:
            raise aiohttp.ClientError(f"status {response.status}")
        body = await response.text()
    return body, (time.monotonic() - start) * 1000.0


async def _probe(session, port, endpoints, timeout, attempts):
    proxy = f"http://127.0.0.1:{port}"
    country = ""
    address = ""
    best = None
    for endpoint in endpoints:
        parser = PARSERS.get(endpoint.get("format", "trace"), _parse_trace)
        for _ in range(max(1, attempts)):
            try:
                body, elapsed = await _fetch(session, endpoint["url"], proxy, timeout)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError,
                    UnicodeDecodeError, ssl.SSLError):
                break
            found, exit_ip = parser(body)
            if not found:
                break
            country = found
            address = exit_ip or address
            best = elapsed if best is None else min(best, elapsed)
        if country:
            break
    if not country or best is None:
        return None
    return country, address, best


async def _run_batch(nodes, core, binary, base_port, config):
    if not nodes:
        return []
    specs = [node.spec for node in nodes]
    builder = cores.build_singbox if core == "sing-box" else cores.build_xray
    context = cores.running(
        binary, builder(specs, base_port), base_port, len(specs), config["startup_timeout"]
    )
    process = await asyncio.to_thread(context.__enter__)
    try:
        if process is None:
            return None
        connector = aiohttp.TCPConnector(limit=0, force_close=True)
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        async with aiohttp.ClientSession(connector=connector, headers=headers, trust_env=False) as session:
            tasks = [
                _probe(
                    session, base_port + index, config["geo_endpoints"],
                    config["verify_timeout"], config["verify_attempts"],
                )
                for index in range(len(nodes))
            ]
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await asyncio.to_thread(context.__exit__, None, None, None)
    verified = []
    for node, outcome in zip(nodes, outcomes):
        if not isinstance(outcome, tuple):
            continue
        country, address, latency = outcome
        node.country = country
        node.exit_ip = address
        node.latency = latency
        verified.append(node)
    return verified


async def _verify_group(nodes, core, binary, base_port, config, depth=0):
    if not nodes:
        return []
    result = await _run_batch(nodes, core, binary, base_port, config)
    if result is not None:
        return result
    if len(nodes) == 1 or depth > 6:
        return []
    middle = len(nodes) // 2
    left = await _verify_group(nodes[:middle], core, binary, base_port, config, depth + 1)
    right = await _verify_group(nodes[middle:], core, binary, base_port, config, depth + 1)
    return left + right


def assign_cores(nodes):
    grouped = {"sing-box": [], "xray": []}
    for node in nodes:
        core = cores.core_for(node.spec)
        if core:
            grouped[core].append(node)
    return grouped


async def verify(nodes, binaries, config, progress=None):
    grouped = assign_cores(nodes)
    verified = []
    base_port = config["verify_base_port"]
    size = max(1, int(config["verify_batch"]))
    for core, items in grouped.items():
        binary = binaries.get(core)
        if not binary or not items:
            continue
        for start in range(0, len(items), size):
            chunk = items[start:start + size]
            outcome = await _verify_group(chunk, core, binary, base_port, config)
            verified.extend(outcome)
            if progress is not None:
                progress(core, start + len(chunk), len(items), len(verified))
            base_port += size + 2
            if base_port > 60000:
                base_port = config["verify_base_port"]
    return verified
