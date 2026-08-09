import requests
import re
import time
from datetime import datetime

API_KEY = "Put Your APi KEY"

RUN_DATE = datetime.now().strftime("%d/%m/%Y")

def is_ip(ioc):
    return re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc)

def calculate_severity(malicious):
    if malicious == 0:
        return "Clean"
    elif malicious <= 2:
        return "Low"
    elif malicious <= 10:
        return "Medium"
    else:
        return "High"

def check_vt(ioc):
    headers = {"x-apikey": API_KEY}

    if is_ip(ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    try:
        r = requests.get(url, headers=headers)

        if r.status_code != 200:
            return f"{ioc},{RUN_DATE},ERROR,{r.status_code}"

        data = r.json()
        attr = data["data"]["attributes"]

        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected
        severity = calculate_severity(malicious)

        results = attr.get("last_analysis_results", {})
        malicious_vendors = []

        for vendor, result in results.items():
            if result.get("category") == "malicious":
                malicious_vendors.append(vendor)

        vendors_str = " | ".join(malicious_vendors[:10])

        tags = attr.get("tags", [])
        tags_str = " | ".join(tags)

        apt_keywords = ["apt", "c2", "botnet", "trojan", "rat"]
        apt_flag = "YES" if any(k in str(tags).lower() for k in apt_keywords) else "NO"

        country = attr.get("country", "N/A")
        asn = attr.get("asn", "N/A")
        as_owner = attr.get("as_owner", "N/A")
        reputation = attr.get("reputation", 0)

        return f"{ioc},{RUN_DATE},{malicious}/{total_engines},{severity},{reputation},{country},{asn},{as_owner},{apt_flag},{vendors_str},{tags_str}"

    except Exception as e:
        return f"{ioc},{RUN_DATE},ERROR,{str(e)}"


def main():
    input_file = "iocs.txt"
    output_file = "vt_results.csv"

    with open(input_file) as f:
        iocs = [line.strip() for line in f if line.strip()]

    with open(output_file, "w", encoding="utf-8") as out:
        out.write("IOC,ScanDate,DetectionRatio,Severity,Reputation,Country,ASN,AS_Owner,APT_Flag,Vendors,Tags\n")

        for ioc in iocs:
            print(f"[+] Checking: {ioc}")
            result = check_vt(ioc)
            out.write(result + "\n")
            time.sleep(15)

    print("\n✅ Done! Results saved in vt_results.csv")


if __name__ == "__main__":
    main()

