from fastmcp import FastMCP
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware    #handle api requests
from starlette.middleware import Middleware
import os
import asyncio
import aiosqlite
from hashlib import sha256
from typing import Any, Dict
from datetime import datetime, timedelta

cache_db = "ioc_cache.db"
cache_ttl = 3600

VT_KEY = ""
ABUSEIPDB_KEY = ""
METADEFENDER_KEY = ""
ABUSE_CH_KEY = ""
SHODAN_KEY = ""
CENSYS_KEY = ""
OTX_KEY = ""

load_dotenv()       #load env vars

mcp = FastMCP(name = "indicatorsearch")

@mcp.tool()
def search_ioc_hash(hash: str) -> str:
    """

    :param hash:
    :return:
    """

@mcp.tool()
def search_ioc_ip(ip: str) -> str:
    """

    :param ip:
    :return:
    """

@mcp.tool()
def search_ioc_domain(domain: str) -> str:
    """

    :param domain:
    :return:
    """

@mcp.tool()
def search_group(name: str) -> str:
    """

    :param name:
    :return:
    """

