import asyncio

from openai import AsyncOpenAI

from ioc_insight.config import AIConfig

async def main():
    cfg = AIConfig()
    client = AsyncOpenAI(base_url=cfg.base_url, api_key=cfg.resolved_key(), timeout=60)
    resp = await client.chat.completions.create(
        model=cfg.model,
        messages=[{"role": "user", "content": "Say OK"}],
        max_tokens=4096, temperature=0.2,
    )
    c = resp.choices[0]
    print("finish:", c.finish_reason)
    print("content:", repr(c.message.content))
    print("reasoning:", repr((c.message.model_dump().get("reasoning_content") or "")[:100]))

asyncio.run(main())
