import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "name": "ManyVPN",
    "max_per_country": 3,
    "max_total": 300,
    "whitelist_share": 0.25,
    "min_whitelist": 20,
    "fetch_timeout": 45,
    "fetch_concurrency": 12,
    "max_per_endpoint": 4,
    "tcp_timeout": 3.0,
    "tcp_concurrency": 700,
    "verify_batch": 150,
    "verify_timeout": 8.0,
    "verify_attempts": 2,
    "verify_base_port": 34000,
    "max_verify": 10000,
    "latency_max_ms": 3500,
    "startup_timeout": 25.0,
    "exclude_countries": [],
    "history_url": "",
    "geo_endpoints": [
        {"url": "https://cp.cloudflare.com/cdn-cgi/trace", "format": "trace"},
        {"url": "http://ip-api.com/json/?fields=status,countryCode,query", "format": "ipapi"},
    ],
}


def load(path=None):
    cfg = dict(DEFAULTS)
    target = Path(path) if path else ROOT / "config.json"
    if target.exists():
        user = json.loads(target.read_text(encoding="utf-8"))
        for key, value in user.items():
            cfg[key] = value
    return cfg


def sources(path=None):
    target = Path(path) if path else ROOT / "sources.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    out = []
    for item in data.get("sources", []):
        if not item.get("enabled", True):
            continue
        out.append({
            "url": item["url"],
            "whitelist": bool(item.get("whitelist", False)),
            "label": item.get("label", ""),
        })
    return out
