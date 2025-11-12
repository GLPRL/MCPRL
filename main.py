import os
import httpx
import asyncio
import aiosqlite
from hashlib import sha256
from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta

VT_KEY = ""
ABUSEIPDB_KEY = ""
METADEFENDER_KEY = ""
ABUSE_CH_KEY = ""
SHODAN_KEY = ""
CENSYS_KEY = ""
OTX_KEY = ""

cache_db = "ioc_cache.db"
cache_ttl = 3600

mcp = FastMCP("ioc_scanner")

if __name__ == "__main__":
    mcp.run(transport="stdio")