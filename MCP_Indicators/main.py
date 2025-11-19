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
async def search_ioc_url(url: str) -> dict[str, bool | None | Any] | None:
    """
    Perform a threat-intelligence lookup for a given URL.
    Normalize the URL (strip tracking parameters when needed, enforce lowercase host, etc.)
    Query all available providers and return a unified, structured result including:
        - verdict or threat_score
        - URL category (phishing, malware distribution, C2, scam, spam, etc.)
        - detection counts (malicious, suspicious, clean, unknown)
        - associated malware family or campaign tags
        - redirected or embedded domains/IPs
        - extracted IOCs (domains, IPs, hashes)
        - first_seen and last_seen timestamps
        - raw provider responses
    Use cache when available and handle provider errors gracefully.
    Input: { "url": "<url string>" }
    Output: a JSON object with unified results.
    """
    cached = await get_cached(url)
    if cached:
        return {"cached": True, "data": cached}

@mcp.tool()
async def search_ioc_hash(hash: str) -> dict[str, bool | None | Any] | None:
    """
        Perform a threat-intelligence lookup for a given file hash.
        The hash can be MD5, SHA1, SHA256, or SHA512.
        Query all available providers and return a unified, structured result that includes:
            - hash_type (MD5/SHA1/SHA256/SHA512)
            - threat_score or vendor scores
            - malware family or classification
            - tags and threat labels
            - detection counts (malicious, suspicious, clean, unknown)
            - first_seen and last_seen timestamps
            - any related IOCs (IPs, domains, URLs, other hashes)
            - raw provider responses
        Use cache when available and handle provider errors gracefully.
        Input: { "hash": "<file hash>" }
        Output: a JSON object with unified results from all the given providers.
    """
    cached = await get_cached(hash)
    if cached:
        return {"cached": True, "data": cached}

@mcp.tool()
async def search_ioc_ip(ip: str) -> dict[str, bool | None | Any] | None:
    """
        Scan an IP address (IPv4 / IPv6) using multiple threat-intelligence sources.

        The tool most:
        - Validate and normalize the IP address.
        - Query all available IP reputation and threat-intelligence providers such as:
            Virus Total (IP reports)
            AbuseIPDB (repurtation, categories, scores)
            OTX (pulses, indicators, malware links)
            ThreatFox (malware C2, bots or payload activities)

        - Provide structured fields from each provider:
            * reputation (malicious / suspicious / clean / unknown)
            * geolocation (country, ASN, ISP) if available
            * categories or tags (e.g., "C2", "scanning", "phishing", "botnet")
            * open ports / services (from GreyNoise or similar)
            * malware families or campaigns associated with the IP
            * related domains (reverse DNS, passive DNS)
            * provider_responses (normalized raw results)
        - Produce an aggregated output:
            * final_verdict (malicious / suspicious / clean / unknown)
            * confidence (0–100)
            * summary_text (clear human-readable explanation)

        Input: { "ip": "<ip address>" }
        Use cache when available and handle provider errors gracefully.
        The tool MUST NOT guess or invent data out of no-where, and must only use information from providers.
    """
    cached = await get_cached(ip)
    if cached:
        return {"cached": True, "data": cached}

@mcp.tool()
async def search_ioc_domain(domain: str) -> dict[str, bool | None | Any] | None:
    """
        Scan a domain IOC using multiple threat-intelligence sources.
        Input is a fully qualified domain name (for example: "malicious-domain.com")

        The tool must:
        - Normalize and validate the domain.
        - Query supported providers for domain reputation and intelligence, such as:
        *Virus Total (domain reports)
        *URLHaus (domain/host intelligence)
        *OTX (Domain pulses and indicators)
        *PhishTank (phishing classification)
        *ThreatFox (malware or botnet activity)

        And then:
            Extract and return structured json with these fields:
            reputation (clean/suspicious/malicious/unknown)
            related_ips (A/AAAA records)
            subdomains
            related_urls or paths
            associated malware families
            tags/classifications
            provider_responses (normalized per provider)

        Lastly, aggregate provider verdicts into:
            * Final verdict (clean/suspicious/malicious/unknown)
            * Confidence (0-100)
            * summary_text (brief explanation)

        Input: { "domain": "<fully qualified domain>" }
        Use cache when available and handle provider errors gracefully.
        The tool MUST NOT guess or invent data out of no-where, and must only use information from providers.
    :param domain:
    :return:
    """
    cached = await get_cached(domain)
    if cached:
        return {"cached": True, "data": cached}

@mcp.tool()
async def search_group(group: str) -> dict[str, bool | None | Any] | None:
    """
        Search for a given threat actor, which includes but not limited to:
        APT Groups, Cybercrime Groups, Malware Operators, Ransomware Gangs etc.
        The input is the name or alias of the group, for example:
        APT29, Qilin, FIN7, Lazarus, DragonForce, Wizard Spider.
        The tool will:
        - Normalize actor name,
        - Query external threat intelligence providers that support actor lookups:
            MITRE ATT&CK (groups and techniques), MISP (Event tags, galaxies, attributes),
            OTX (Pulses monitoring the actors), ThreatFox (malware families linked to the actors).

        Return a structured json as dictionary, contains:
            actor name, known aliases, associated malware, associated campaigns, linked TTPs(MITRE techniques),
            related IOCs, provider responses.
        And aggregate all findings to unified summary:
            - Threat level (low, medium, high)
            - Confidence (0-100)
            - summary_text (short human-readable explanation)

        Input: { "group": "<group name or alias>" }
        Use cache when available and handle provider errors gracefully.
        The tool MUST NOT guess or invent data out of no-where, and must only use information from providers.
    """
    cached = await get_cached(group)
    if cached:
        return {"cached": True, "data": cached}
