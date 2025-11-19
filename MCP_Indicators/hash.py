threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"
urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"
urlv4_md = "https://api.metadefender.com/v4"
urlv5_md = "https://api.metadefender.com/v5/threat-intel"
url_vt = "https://www.virustotal.com/api/v3/"
url_otx = "https://otx.alienvault.com/api/v1/"
url_yaraify = "https://yaraify-api.abuse.ch/api/v1/"

def querypayload_abusech(hash, api_key):
    if re.search(r"^[A-Za-z0-9]{32}$", hash):
        hash_alg = 'md5_hash'
    elif re.search(r"^[A-Za-z0-9]{64}$", hash):
        hash_alg = 'sha256_hash'
    else:
        return "Invalid file hash provided"

    data = {
        hash_alg: hash
    }
    headers = {
        "Auth-Key": api_key
    }
    response = requests.post(f"{urlhaus_url}payload/", data=data, headers=headers)
    raw = response.json()

    signature = f"Signature: {raw.get('signature')}"
    file_type = f"\nFile type: {raw.get('file_type')}"
    size = f"\nFile size: {raw.get('file_size')}"
    md5hash = f"\nMD5: {raw.get('md5_hash')}"
    sha256hash = f"\nSHA256: {raw.get('sha256_hash')}"
    firstseen = f"\nFirst seen: {raw.get('firstseen')}"
    lastseen = f"Last seen: {raw.get('lastseen')}"

    vt = raw.get("virustotal", {})
    vtresult = (
        f"\nVirusTotal result (detection/total): {vt.get('result')}"
        f"\nURL: {vt.get('link')}"
    )

    otherhashes = (
        f"\nIMPHash: {raw.get('imphash')}"
        f"\nssdeep: {raw.get('ssdeep')}"
        f"\nTLSH: {raw.get('tlsh')}"
    )

    urllist = raw.get("urls", [])
    prop = "\nPayload is in the following suspected URLs:"
    for entry in urllist:
        prop += (
            f"\n\tURL: {entry.get('url')}"
            f"\n\tStatus: {entry.get('url_status')}"
            f"\n\tFilename: {entry.get('filename')}"
            f"\n\tFirst seen: {entry.get('firstseen')} Last Seen: {entry.get('lastseen')}\n"
        )

    return f"{signature}{file_type}{size}{md5hash}{sha256hash}{firstseen}{lastseen}{vtresult}{otherhashes}{prop}"

def searchbyfilehash_abusech(api_key, hash):
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "query" : "search_hash",
        "hash" : hash
    }
    response = requests.post(threatfox_url, headers=headers, json=data)
    print(response.json())

def analyzehash_md(hash, apikey):
    url = f"{urlv4_md}/hash/{hash}"

    headers = {
        "apikey" : str(apikey)
    }
    response = requests.get(url, headers=headers)
    raw = response.json()
    family = f"Malware Family: {response.json().get('malware_family')}"
    type = f"\nMalware Type: {response.json().get('malware_type')}"
    scanres = raw.get("scan_results")
    total = f"\nTotal detections/Total AVs: \n{scanres.get('total_detected_avs')}/{scanres.get('total_avs')}"
    details = f"\nScan details: {scanres.get('scan_details')}"
    res = f"\nAll results: {scanres.get('scan_all_result_a')}"
    print(f"{family}{type}{total}{details}{res}")

def hashsearch_vt(hash, api_key):
    dest = f"{url_vt}search?query={hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(dest, headers=headers)
    if response.status_code != 200:
        return response.text
    else:
        raw = response.json().get("data")[0]
        attr = raw.get('attributes')
        type = f"\nType: {attr.get('type_tag')} Desc: {attr.get('type_description')}"
        tlsh = f"\nTLSH: {attr.get('tlsh')}"
        names = (f"\nMeaningful name: {attr.get('meaningful_name')}"
                 f"\nOther names: {attr.get('names')}")
        tags = f"\nTags: {attr.get('tags')}"
        sigma = f"\nSigma results: {attr.get('sigma_analysis_results')}"
        sandbox = f"\nSandboxes results: {attr.get('sandbox_verdicts')}"
        classifications = f"\nPopular Threat classifications: {attr.get('popular_threat_classification')}"
        stats = attr.get('last_analysis_stats')
        statistics = (
            f"\nMalicious: {stats.get('malicious')}"
            f"\nSuspicious: {stats.get('suspicious')}"
            f"\nUndetected: {stats.get('undetected')}"
            f"\nHarmless: {stats.get('harmless')}"
                      )

        return f"{names}{type}{tlsh}{tags}{statistics}{classifications}{sandbox}{sigma}"

def check_ioc_filehash_otx(self, filehash, section="general"):
    headers = {
        "X-OTX-API-KEY": self.__api_key
    }
    res = requests.get(f"{url_otx}indicators/file/{filehash}/{section}")
    if res.status_code == 200:
        pretty = clean_json_structure(res.json())
        return pretty
    else:
        return f"Error {res.status_code}: {res.text}"

def queryhash_yaraify(hash, token = ""):
    headers = {
        "Accept": "application/json",
    }

    data = {
        "query": "lookup_hash",
        "search_term": hash,
        "malpedia-token": token
    }

    response = requests.post(url_yaraify, headers = headers, json = data)
    print(response.json())
