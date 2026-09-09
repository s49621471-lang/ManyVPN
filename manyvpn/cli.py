import argparse
import asyncio
import os
import shutil
import sys
import time
from pathlib import Path

from . import fetch, probe, render, select, settings, state, verify, whitelist


def _log(message):
    print(f"[manyvpn] {message}", flush=True)


def _resolve(binary, explicit):
    if explicit:
        return explicit if Path(explicit).exists() else ""
    found = shutil.which(binary)
    return found or ""


def _write(directory, name, content):
    path = directory / name
    path.write_text(content, encoding="utf-8")
    _log(f"wrote {path} ({len(content.encode('utf-8'))} bytes)")


async def run(args):
    started = time.monotonic()
    config = settings.load(args.config)
    if args.max_verify:
        config["max_verify"] = args.max_verify
    if args.max_total:
        config["max_total"] = args.max_total
    sources = settings.sources(args.sources)
    if args.limit_sources:
        sources = sources[:args.limit_sources]
    _log(f"sources: {len(sources)}")

    nodes, report = await fetch.collect(
        sources, config["fetch_timeout"], config["fetch_concurrency"]
    )
    working_sources = sum(1 for item in report if item["nodes"] > 0)
    _log(f"fetched {len(nodes)} configs from {working_sources}/{len(sources)} sources")
    for item in report:
        if item["error"]:
            _log(f"  source failed: {item['error']} {item['url']}")

    whitelist.apply(nodes)
    nodes = select.dedupe(nodes, config["max_per_endpoint"])
    _log(f"after dedupe: {len(nodes)}")

    history_path = Path(args.history)
    history = state.load(history_path)
    _log(f"history entries: {len(history['nodes'])}")

    if not args.skip_tcp:
        nodes = await probe.alive(nodes, config["tcp_timeout"], config["tcp_concurrency"])
        _log(f"tcp reachable: {len(nodes)}")

    candidates = select.prioritize(nodes, config["max_verify"], history)
    _log(f"candidates for deep check: {len(candidates)}")

    binaries = {
        "sing-box": _resolve("sing-box", args.singbox),
        "xray": _resolve("xray", args.xray),
    }
    _log(f"cores: sing-box={binaries['sing-box'] or 'missing'} xray={binaries['xray'] or 'missing'}")
    if not any(binaries.values()):
        _log("no proxy core available, aborting")
        return 2

    def progress(core, done, total, verified):
        _log(f"  {core}: {done}/{total} checked, {verified} verified")

    verified = await verify.verify(candidates, binaries, config, progress)
    _log(f"verified working: {len(verified)}")
    if not verified:
        _log("nothing verified, aborting without overwriting output")
        return 3

    state.record(history, candidates, verified)
    state.save(history, history_path)

    normal, white, stats = select.choose(verified, config, history)
    _log(f"selected: {len(normal)} normal + {len(white)} whitelist across "
         f"{stats['countries_normal']}/{stats['countries_whitelist']} countries")

    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=True)
    title = config["name"]
    _write(directory, "manyvpn.txt", render.encoded(normal, white))
    _write(directory, "manyvpn-plain.txt", render.plain(normal, white))
    _write(directory, "manyvpn-singbox.json", render.singbox(normal, white, title))
    _write(directory, "manyvpn-clash.yaml", render.clash(normal, white, title))
    _write(directory, "status.json", render.status(normal, white, {
        **stats,
        "fetched": len(nodes),
        "candidates": len(candidates),
        "verified": len(verified),
        "sources_ok": working_sources,
        "sources_total": len(sources),
        "duration_sec": round(time.monotonic() - started, 1),
    }, report, title))
    _write(directory, "README.md", render.summary(normal, white, {
        **stats,
        "fetched": len(nodes),
        "candidates": len(candidates),
        "verified": len(verified),
        "sources_ok": working_sources,
        "sources_total": len(sources),
        "duration_sec": round(time.monotonic() - started, 1),
    }, args.repo, args.branch, title))
    shutil.copyfile(history_path, directory / "history.json")
    _log(f"done in {round(time.monotonic() - started, 1)}s")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="manyvpn")
    parser.add_argument("--config", default="")
    parser.add_argument("--sources", default="")
    parser.add_argument("--output", default="sub")
    parser.add_argument("--history", default="state/history.json")
    parser.add_argument("--singbox", default="")
    parser.add_argument("--xray", default="")
    parser.add_argument("--max-verify", type=int, default=0)
    parser.add_argument("--max-total", type=int, default=0)
    parser.add_argument("--limit-sources", type=int, default=0)
    parser.add_argument("--skip-tcp", action="store_true")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "s49621471-lang/ManyVPN"))
    parser.add_argument("--branch", default=os.environ.get("PUBLISH_BRANCH", "sub"))
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
