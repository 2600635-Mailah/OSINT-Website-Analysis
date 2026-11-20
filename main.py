
import os
import requests
import pandas as pd
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load API keys from .env file
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

print("OSINT Website Analysis Tool")
print("API configuration loaded successfully.")

print("\nChecking API keys...")

keys = {
    "VirusTotal": VT_API_KEY,
    "WhoisXML": WHOIS_API_KEY,
    "AlienVault OTX": ALIENVAULT_API_KEY,
    "Google Safe Browsing": GOOGLE_API_KEY
}

for tool, key in keys.items():
    if key:
        print(f"{tool}: API key loaded")
    else:
        print(f"{tool}: API key missing")

def get_target_website():
    website = input("\nEnter target website (e.g. example.com): ").strip()

    if not website:
        print("Error: Website cannot be empty.")
        return None

    if not website.startswith(("http://", "https://")):
        website = "https://" + website

    from urllib.parse import urlparse
    domain = urlparse(website).hostname

    if not domain or "." not in domain:
        print("Error: Please enter a valid website.")
        return None

    return website, domain


target = get_target_website()

if target:
    website, domain = target
    print("\nTarget Website:", website)
    print("Target Domain:", domain)

def analyze_virustotal(domain):
    print("\nChecking VirusTotal...")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            print("VirusTotal Results:")
            print("Malicious:", stats.get("malicious", 0))
            print("Suspicious:", stats.get("suspicious", 0))
            print("Harmless:", stats.get("harmless", 0))
            print("Undetected:", stats.get("undetected", 0))

            return stats

        else:
            print("VirusTotal Error:", response.status_code)
            return {"error": response.text[:300]}

    except requests.RequestException as error:
        print("Connection Error:", error)
        return {"error": str(error)}


if target:
    vt_results = analyze_virustotal(domain)

def analyze_whois(domain):
    print("\nChecking WhoisXML...")

    url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    params = {
        "apiKey": WHOIS_API_KEY,
        "domainName": domain,
        "outputFormat": "JSON"
    }

    try:
        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            record = data.get("WhoisRecord", {})

            registrar = record.get("registrarName", "Not available")
            created = record.get("createdDate", "Not available")
            expires = record.get("expiresDate", "Not available")

            print("WhoisXML Results:")
            print("Registrar:", registrar)
            print("Created:", created)
            print("Expires:", expires)

            return {
                "registrar": registrar,
                "created": created,
                "expires": expires
            }

        else:
            print("WhoisXML Error:", response.status_code)
            return {"error": response.text[:300]}

    except requests.RequestException as error:
        print("Connection Error:", error)
        return {"error": str(error)}


if target:
    whois_results = analyze_whois(domain)

def analyze_alienvault(domain):
    print("\nChecking AlienVault OTX...")

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    headers = {
        "X-OTX-API-KEY": ALIENVAULT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()

            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)

            print("AlienVault Results:")
            print("Threat Intelligence Pulses:", pulse_count)

            return {
                "pulse_count": pulse_count,
                "reputation": data.get("reputation", "Not available"),
                "indicator": domain
            }

        else:
            print("AlienVault Error:", response.status_code)
            return {"error": response.text[:300]}

    except requests.RequestException as error:
        print("Connection Error:", error)
        return {"error": str(error)}


if target:
    alienvault_results = analyze_alienvault(domain)



def analyze_google_safe_browsing(website):
    print("\nChecking Google Safe Browsing...")

    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    params = {
        "key": GOOGLE_API_KEY
    }

    payload = {
        "client": {
            "clientId": "OSINTWebsiteAnalysis",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": website}
            ]
        }
    }

    try:
        response = requests.post(
            url,
            params=params,
            json=payload,
            timeout=30
        )

        print("HTTP Status:", response.status_code)

        if response.status_code == 200:
            data = response.json()
            threats = data.get("matches", [])

            print("Google Safe Browsing Results:")

            if threats:
                for threat in threats:
                    print("Threat Type:", threat.get("threatType"))
                    print("Threat URL:", threat.get("threat", {}).get("url"))
            else:
                print("No known threats found.")

            return {
                "threat_count": len(threats),
                "threats": threats
            }

        else:
            print("Google API Error:", response.text[:500])
            return {"error": response.text[:500]}

    except requests.RequestException as error:
        print("Connection Error:", error)
        return {"error": str(error)}

    except ValueError as error:
        print("JSON Error:", error)
        return {"error": str(error)}
if target:
    google_results = analyze_google_safe_browsing(website)