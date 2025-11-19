from fastmcp import FastMCP
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware    #handle api requests
from starlette.middleware import Middleware
import os
import asyncio
import aiosqlite
from hashlib import sha256
from typing import Any, Dict, Coroutine
from datetime import datetime, timedelta

cache_db = "ioc_cache.db"
cache_ttl = 1800    # 30 minutes cache

VT_KEY = ""
ABUSEIPDB_KEY = ""
METADEFENDER_KEY = ""
ABUSE_CH_KEY = ""
SHODAN_KEY = ""
CENSYS_KEY = ""
OTX_KEY = ""

load_dotenv()       #load env vars

mcp = FastMCP(name = "indicatorsearch")


async def init_cache():
    """
        DB Initialization
    :return: none
    """
    async with aiosqlite.connect(cache_db) as db:
        await db.execute("""
                    CREATE TABLE IF NOT EXISTS cache (
                        ioc TEXT PRIMARY KEY,
                        result TEXT,
                        timestamp INTEGER
                    )
                """)
        await db.commit()

async def get_cached(obj: str):
    """
        Cache lookup
    :param ioc:
    :return:
    """
    async with aiosqlite.connect(cache_db) as db:
        cur = await db.execute(
            "SELECT result, timestamp FROM cache WHERE ioc = ?", (obj,)
        )
        row = await cur.fetchone()
        if not row:
            return None

        result, ts = row
        if (datetime.utcnow().timestamp() - ts) > cache_ttl:
            return None  # expired

        return json.loads(result)

async def save_cache(ioc: str, result: dict):
    """
        Save ioc and search result to cache, for later lookups if needed.
    :param ioc:
    :param result:
    :return:
    """
    async with aiosqlite.connect(cache_db) as db:
        await db.execute(
            "REPLACE INTO cache (ioc, result, timestamp) VALUES (?, ?, ?)",
            (ioc, json.dumps(result), int(datetime.utcnow().timestamp()))
        )
        await db.commit()

@mcp.tool()
async def search_ioc_hash(hash: str) -> dict[str, bool | None | Any] | None:
    cached = await get_cached(hash)
    if cached:
        return {"cached": True, "data": cached}
    """

    :param hash:
    :return:
    """

@mcp.tool()
async def search_ioc_ip(ip: str) -> dict[str, bool | None | Any] | None:
    cached = await get_cached(ip)
    if cached:
        return {"cached": True, "data": cached}
    """

    :param ip:
    :return:
    """

@mcp.tool()
async def search_ioc_domain(domain: str) -> dict[str, bool | None | Any] | None:
    cached = await get_cached(domain)
    if cached:
        return {"cached": True, "data": cached}
    """

    :param domain:
    :return:
    """

@mcp.tool()
async def search_group(group: str) -> dict[str, bool | None | Any] | None:
    cached = await get_cached(group)
    if cached:
        return {"cached": True, "data": cached}
    """

    :param name:
    :return:
    """

