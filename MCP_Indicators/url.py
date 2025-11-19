url_otx = "https://otx.alienvault.com/api/v1/"
urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"

def queryurl_abusech(link, api_key):
    headers = {
        "Auth-Key": api_key
    }
    data = {
        "url": link
    }
    response = requests.post(f"{urlhaus_url}url/", data=data, headers=headers)
    if response.status_code == 200:
        raw = response.json()
        ref = f"Reference: {raw.get('urlhaus_reference')}"
        status = f"\nStatus: {raw.get('url_status')}"
        ip = f"\nIP: {raw.get('host')}"
        dateadd = f"\nAdded on: {raw.get('date_added')}"
        lastseen = f", Last online: {raw.get('last_online')}"
        threat = f"\nThreats: {raw.get('threat')}"
        taglist = "\nTags: "
        tags = raw.get("tags", [])
        for tag in tags:
            taglist += f"{tag} "

        payloads = raw.get("payloads", [])
        payloadlist = "\nPayloads:\n"
        for payload in payloads:
            payloadlist += f"{payload}\n"

        return f"{ref}{status}{ip}{dateadd}{lastseen}{threat}{taglist}{payloadlist}"

def check_ioc_url_otx(self, ioc_url, section="general"):
    headers = {
        "X-OTX-API-KEY": self.__api_key
    }

    res = requests.get(f"{url_otx}indicators/url/{ioc_url}/{section}", headers=headers)
    if res.status_code == 200:
        pretty = clean_json_structure(res.json())
        return pretty
    else:
        return f"Error {res.status_code}: {res.status_code} - {res.text}"
