"""Verify all four services are up before running any agent code."""

import os
import asyncio
import httpx
from neo4j import AsyncGraphDatabase
from dotenv import load_dotenv

load_dotenv()


async def check_neo4j():
    driver = AsyncGraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]),
    )
    await driver.verify_connectivity()
    await driver.close()
    print("✓ Neo4j")


async def check_qdrant():
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{os.environ['QDRANT_URL']}/healthz")
        r.raise_for_status()
    print("✓ Qdrant")


async def check_redis():
    import redis.asyncio as aioredis

    r = await aioredis.from_url(os.environ["REDIS_URL"])
    await r.ping()
    await r.aclose()
    print("✓ Redis")


async def main():
    print("Running health checks...")
    await asyncio.gather(check_neo4j(), check_qdrant(), check_redis())
    print("\nAll services healthy.")


if __name__ == "__main__":
    asyncio.run(main())
