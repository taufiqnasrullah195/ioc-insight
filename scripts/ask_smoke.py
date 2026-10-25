import asyncio

from ioc_insight.ai.client import AIClient
from ioc_insight.config import load_config
from ioc_insight.db import HistoryDB


async def main():
    cfg = load_config()
    db = HistoryDB("data/history.db")
    items = db.list(limit=50)["items"]
    db.close()
    print(f"history items: {len(items)}")
    answer = await AIClient(cfg.ai).ask(
        "IOC mana saja yang pernah divonis MALICIOUS? Jawab singkat.", items, "id"
    )
    print("ANSWER:", answer)


asyncio.run(main())
