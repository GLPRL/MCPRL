ransomware_live = "https://api.ransomware.live/v2"
HEADERS = {"Accept": "application/json"}
#TODO

def groupvictims_rw_live(group):
    raw = get(f"/groupvictims/{group}")
    if isinstance(raw, dict) and "error" in raw:
        return raw["error"]

    text = f"======= {group}'s Victims =======\n\n"
    for item in raw:
        text += (f"Sector: {item.get('activity')}, Victim: {item.get('victim')},\n"
                 f"Domain: {item.get('domain')}\n"
                 f"Date: {item.get('attackdate')}, Discovered: {item.get('discovered')}\n"
                 f"Claim URL: {item.get('claim_url')}\n"
                 f"Country: {item.get('country')}\n"
                 f"Description: {item.get('description')}\n"
                 f"Infostealer Data: {item.get('infostealer_data')}\n"
                 f"Press Data: {item.get('press')}\n"
                 f"Screenshot URL: {item.get('screenshot')}\n"
                 f"URL: {item.get('url')}\n"
                 f"------------\n\n")
    return text