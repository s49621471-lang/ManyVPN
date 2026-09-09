import asyncio
import time


async def _check(node, timeout, semaphore, results):
    async with semaphore:
        start = time.monotonic()
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(node.server, node.port), timeout=timeout
            )
            node.latency = (time.monotonic() - start) * 1000.0
            results.append(node)
        except (asyncio.TimeoutError, OSError, ValueError):
            return
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass


async def alive(nodes, timeout=3.0, concurrency=700):
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    tasks = [_check(node, timeout, semaphore, results) for node in nodes]
    for start in range(0, len(tasks), 5000):
        await asyncio.gather(*tasks[start:start + 5000])
    return results
