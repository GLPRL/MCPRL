urlv4_md = "https://api.metadefender.com/v4"
urlv5_md = "https://api.metadefender.com/v5/threat-intel"
urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"
url_vt = "https://www.virustotal.com/api/v3/"
url_otx = "https://otx.alienvault.com/api/v1/"


def iplookup_md(ip, apikey):
    url = f"{urlv4}/ip/{ip}"
    headers = {
        "apikey" : str(apikey)
    }

    response = requests.get(url, headers=headers)
    raw = response.json()
    detections = raw.get("lookup_results").get("detected_by")
    sources = raw.get("lookup_results").get("sources")
    list = ""
    for source in sources:
        if source.get("assessment") != "":
            list += "\nProvider: " + source.get("provider") + ", Assessment: " + source.get("assessment")

    location = "\nGeo Location: " + raw.get("geo_info").get("country").get("name") + ", City: " + raw.get("geo_info").get("city").get("name")

    result = f"Detection Count: {detections}\nSummary:{list}{location}"
    return result

def ipscan_vt(ip, api_key):
    dest = f"{url_vt}/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(dest, headers=headers)
    if response.status_code != 200:
        return response.text

    else:
        raw = response.json().get("data").get("attributes")
        country = raw.get("country")
        rep = f"Reputation: {raw.get('reputation')}"
        asowner = f"\nAS-Owner: {raw.get('as_owner')}, ASN: {raw.get('asn')}"
        whois = f"\nWHOis Information: {raw.get('whois')}"
        tags = raw.get('tags')
        taglist = "Tags: "
        for tag in tags:
            taglist += tag + " "
        stats = (
            f"\nResult Stats:\nMalicious: {raw.get('last_analysis_stats').get('malicious')}\nSuspicious: "
            f"{raw.get('last_analysis_stats').get('suspicious')}\nUndetected: {raw.get('last_analysis_stats').get('undetected')}\n"
            f"Harmless: {raw.get('last_analysis_stats').get('harmless')}"
                 )

        return f"{country}\n{rep}{asowner}\n{taglist}{stats}{whois}"

def check_ioc_ipv4_otx(self, ip, section="general"):
    headers = {
        "X-OTX-API-KEY": self.__api_key
    }
    res = requests.get(f"{url_otx}indicators/IPv4/{ip}/{section}")
    if res.status_code == 200:
        pretty = clean_json_structure(res.json())
        return pretty
    else:
        return f"Error {res.status_code}: {res.text}"

#section: general, reputation, geo, malware, url_list, passive_dns
def check_ioc_ipv6_otx(self, ip, section="general"):
    headers = {
        "X-OTX-API-KEY": self.__api_key
    }
    res = requests.get(f"{url_otx}indicators/IPv4/{ip}/{section}")
    if res.status_code == 200:
        pretty = clean_json_structure(res.json())
        return pretty

    else:
        return f"Error {res.status_code}: {res.text}"