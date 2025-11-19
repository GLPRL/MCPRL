threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"
url_vt = "https://www.virustotal.com/api/v3/"

def search_vt(item, api_key):
    dest = f"{url}search?query={item}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(dest, headers=headers)
    if response.status_code != 200:
        return

    else:
        raw = response.json().get("data")

        if raw and isinstance(raw, list) and len(raw) > 0:
            attr = raw[0].get('attributes', {})

            # Threat names
            threat_names = attr.get('threat_names', [])
            threat_name_str = f"Threat Names: {', '.join(threat_names)}" if threat_names else "\nThreat Names: None"

            # Crowdsourced context
            context_list = attr.get('crowdsourced_context', [])
            if context_list:
                context = context_list[0]
                crowdsource_context = (
                    f"\nTitle: {context.get('title', 'N/A')}"
                    f"\nInfo: {context.get('details', 'N/A')}"
                    f"\nSeverity: {context.get('severity', 'N/A')}"
                )
            else:
                crowdsource_context = "\nNo crowdsourced context available."
            stats = attr.get('last_analysis_stats', {})
            statistics = (
                f"\nMalicious: {stats.get('malicious', 0)}"
                f"\nSuspicious: {stats.get('suspicious', 0)}"
                f"\nUndetected: {stats.get('undetected', 0)}"
                f"\nHarmless: {stats.get('harmless', 0)}"
            )
            reputation = f"\nReputation: {attr.get('reputation', 'N/A')}"
            result = f"{threat_name_str}{crowdsource_context}{statistics}{reputation}"
            return result
        else:
            return "No data available."

def searchioc(api_key, text, exact_match=False):
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "query": "search_ioc",
        "search_term": text,
        "exact_match": exact_match
    }

    try:
        response = requests.post(threatfox_url, headers=headers, json=data)
        response.raise_for_status()
        json_data = response.json()
        if json_data.get("query_status") == "ok":
            return json_data
        else:
            print("Query error:", json_data.get("error", "Unknown error"))
            return None
    except requests.RequestException as e:
        print("Request failed:", e)
        return None