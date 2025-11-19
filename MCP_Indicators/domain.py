urlv4_md = "https://api.metadefender.com/v4"
url_vt = "https://www.virustotal.com/api/v3/"
url_otx = "https://otx.alienvault.com/api/v1/"


def domainscan_md(domain, apikey):
    url = f"{urlv4_md}/domain/{domain}"
    headers = {
        "apikey" : str(apikey)
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        raw = response.json().get("lookup_results")
        detectcount = f"Total Detections: {raw.get('detected_by')}"
        src = raw.get("sources", [])
        srclist = "\nSummary:"
        for source in src:
            assessment = source.get("assessment") if source.get("assessment") else "No Assessment"
            srclist += (
                f"\nProvider: {source.get('provider')}, "
                f"Assessment: {assessment}, "
                f"Reason: {source.get('category')}"
            )
        return f"Detections for {domain}:\n{detectcount}{srclist}"
    else:
        return response.json()

def domainscan_vt(domain, api_key):
    dest = f"{url}/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(dest, headers=headers)
    if response.status_code != 200:
        return f"Scan failed:\nCode{response.status_code}\n{response.text}"

    else:
        raw = response.json().get("data").get("attributes")
        nsrecords = raw.get("last_dns_records")
        nsrec = "Last NS Records:"
        for record in nsrecords:
            nsrec += f"\n{record.get('type')} | {record.get('ttl')} | {record.get('value')}"
        rep = f"\nDomain Reputation: {raw.get('reputation')}"
        categories = f"\nAttack Categories: {raw.get('categories')}"
        tags = f"\nTags: {raw.get('tags')}"
        stats = raw.get('last_analysis_stats')
        mal = f"\nMalicious: {stats.get('malicious')}"
        sus = f"\nSuspicious: {stats.get('suspicious')}"
        undet = f"\nUndetected: {stats.get('undetected')}"
        harml = f"\nHarmless: {stats.get('harmless')}"
        return f"{nsrec}{rep}{categories}{tags}\nStatistics:{mal}{sus}{undet}{harml}"

def check_ioc_domain_otx(self, domain, section="general"):
    headers = {
        "X-OTX-API-KEY": self.__api_key
    }
    res = requests.get(f"{url_otx}indicators/domain/{domain}/{section}")
    if res.status_code == 200:
        pretty = clean_json_structure(res.json())
        return pretty
    else:
        return f"Error {res.status_code}: {res.text}"
