# MCP_Indicators
Is an MCP server to help automate searching for IOCs (Indicators of Compromise)
and APT group search (Ransomware gangs, Malware Operators, etc.)
## Supported IOCs
- URL
- Domain
- IP
- File hashes

## Platforms
Using simple python's requests library, the MCP server queries various tools and threat intelligence platforms.</br>
Currently, the tool supports:
VirusTotal</br>
AbuseCH</br>
MetaDefender</br>
OTX</br></br>
Planned tools for support in the future:
Shodan<br>
HASH lookup<br>
MalShare</br>
Hybrid-Analysis</br>
AbuseIPDB</br>
GreyNoise</br>
PhishTank</br>
MITRE ATT&CK API</br>

## Run instructions
### Cursor locally (SSE):
`uv run --with fastmcp fastmcp run PATH\MCP_Indicators\main.py --port {port}`
</br>Configuration:</br>
`Config (in mcp.json):
"indicatorsearch": {
  "url": "http://127.0.0.1:8000/mcp",
  "transport": "sse"
}`
### Claude:


<br>
### Claude:


This tool is free to use,</br>
there is no data collection whatsoever. The tool was tested on:
- Claude Desktop
- Cursor

The tool requires creating API keys for the beforementioned platforms,
so it requires to grab the keys from which-ever vault/location they are stored on,
and be added on the [main.py](https://github.com/GLPRL/MCPRL/blob/main/MCP_Indicators/main.py) file,
and the API keys are required to be inserted ONLY THERE.
* It is recommended not to paste those keys as plain text.

## Use examples

- Give me information about X (Replace with actualy name) APT group.
Information regarding domains, urls, IPs and file associated with them as well

