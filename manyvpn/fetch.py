import asyncio
import re

import aiohttp

from . import parse

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
CLASH_HINT = re.compile(r"^\s*proxies\s*:", re.MULTILINE)


def _decode_payload(text):
    if any(scheme in text for scheme in parse.SCHEMES):
        return text
    decoded = parse.b64decode(text)
    if any(scheme in decoded for scheme in parse.SCHEMES):
        return decoded
    return text


def _from_clash(text):
    try:
        import yaml
    except ImportError:
        return []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return []
    return [item for item in proxies if isinstance(item, dict)]


async def _get(session, url, timeout, retries=2):
    last = None
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status != 200:
                    last = f"HTTP {response.status}"
                    if response.status in (429, 500, 502, 503):
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    return None, last
                raw = await response.read()
                return raw.decode("utf-8", "ignore"), ""
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            last = type(exc).__name__
            await asyncio.sleep(1.5 * (attempt + 1))
    return None, last or "failed"


async def _one(session, source, timeout, semaphore, report):
    async with semaphore:
        text, error = await _get(session, source["url"], timeout)
    label = source.get("label") or source["url"]
    if text is None:
        report.append({"source": label, "url": source["url"], "nodes": 0, "error": error})
        return []
    payload = _decode_payload(text)
    nodes = parse.extract(payload, source["url"], source["whitelist"])
    if not nodes and CLASH_HINT.search(payload):
        from . import clash
        nodes = clash.extract(_from_clash(payload), source["url"], source["whitelist"])
    report.append({"source": label, "url": source["url"], "nodes": len(nodes), "error": ""})
    return nodes


async def collect(sources, timeout=45, concurrency=12):
    semaphore = asyncio.Semaphore(concurrency)
    report = []
    connector = aiohttp.TCPConnector(limit=concurrency * 2)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    async with aiohttp.ClientSession(connector=connector, headers=headers, trust_env=True) as session:
        tasks = [_one(session, source, timeout, semaphore, report) for source in sources]
        results = await asyncio.gather(*tasks)
    nodes = []
    for batch in results:
        nodes.extend(batch)
    report.sort(key=lambda item: item["nodes"], reverse=True)
    return nodes, report
