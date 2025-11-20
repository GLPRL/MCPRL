import requests
from urllib.parse import quote

def queryurl_abusech(link: str, api_key: str) -> dict:
    """Return raw JSON from URLhaus / AbuseCh"""
    try:
        headers = {
            "Auth-Key": api_key
        }
        data = {
            'url': link
        }
        resp = requests.post(f"https://urlhaus-api.abuse.ch/v1/url/", data, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def check_ioc_url_otx(ioc_url: str, key: str, section="general") -> dict:
    """Return raw JSON from AlienVault OTX"""
    try:
        headers = {"X-OTX-API-KEY": key}
        url_encoded = quote(ioc_url, safe="")
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/url/{url_encoded}/{section}", headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()  # raw JSON only
    except Exception as e:
        return {"error": str(e)}

def search_vt(item: str, api_key: str) -> dict:
    """Return raw JSON from VirusTotal search"""
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }
        payload = {"url": item}

        response = requests.post("https://www.virustotal.com/api/v3/urls", data=payload, headers=headers)
        response.raise_for_status()
        return resp.json()  # raw JSON only
    except Exception as e:
        return {"error": str(e)}
