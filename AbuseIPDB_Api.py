import csv
import ipaddress
import os
import re
import sys
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INPUT_FILE = "iocs.txt"
OUTPUT_FILE = "abuseipdb_enriched.csv"

MAX_AGE_DAYS = 90
TIMEOUT = 20
#Get your API Key from the website after login
API_KEY = "Put your API"

RUN_DATE = datetime.now().strftime("%d/%m/%Y")

if not API_KEY.strip():
    print("❌ API key empty")
    sys.exit()

session = requests.Session()
session.headers.update({
    "Key": API_KEY,
    "Accept": "application/json",
    "User-Agent": "ThreatIntel-Enrichment/6.0"
})

retries = Retry(
    total=5,
    connect=3,
    read=3,
    backoff_factor=2,
    status_forcelist=[429,500,502,503,504],
    allowed_methods=["GET"]
)

adapter = HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)

PATTERNS=[
(r"sshd|ssh","SSH Brute Force"),
(r"authentication failure","Authentication Failure"),
(r"invalid user","Invalid User"),
(r"honeypot","Honeypot Hit"),
(r"mod_security","Web Attack"),
(r"cgi-bin","Directory Traversal"),
(r"scan|port","Port Scan"),
(r"smtp|mail","SMTP Abuse"),
(r"rdp","RDP Activity"),
(r"powershell","PowerShell"),
(r"sql","SQL Injection"),
(r"exploit","Exploitation"),
(r"bot|malware","Bot Activity"),
(r"spam","Spam")
]

def parse_comment(comment):
    text=str(comment).lower()
    found=set()
    for pattern,label in PATTERNS:
        if re.search(pattern,text):
            found.add(label)
    if not found:
        found.add("Unknown Activity")
    return found

def calculate_severity(score):
    score=int(score)
    if score>=90: return "CRITICAL"
    elif score>=70: return "HIGH"
    elif score>=40: return "MEDIUM"
    return "LOW"

def valid_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def check_ip(ip):
    if not valid_ip(ip):
        return {
            "IP":ip,
            "ScanDate":RUN_DATE,
            "Status":"Skipped",
            "Error":"Invalid IP"
        }

    url="https://api.abuseipdb.com/api/v2/check"
    params={"ipAddress":ip,"maxAgeInDays":MAX_AGE_DAYS,"verbose":"true"}

    try:
        r=session.get(url,params=params,timeout=TIMEOUT)

        if r.status_code!=200:
            return {
                "IP":ip,
                "ScanDate":RUN_DATE,
                "Status":"Error",
                "Error":f"HTTP {r.status_code}"
            }

        data=r.json()["data"]
        score=data.get("abuseConfidenceScore",0)
        reports=data.get("totalReports",0)
        activities=set()

        for report in data.get("reports",[]):
            activities.update(parse_comment(report.get("comment","")))

        return {
            "IP":ip,
            "ScanDate":RUN_DATE,
            "Reports":reports,
            "Country":data.get("countryCode",""),
            "ISP":data.get("isp",""),
            "Severity":calculate_severity(score),
            "AbuseScore":score,
            "ASN":data.get("asn",""),
            "LastReported":data.get("lastReportedAt",""),
            "UsageType":data.get("usageType",""),
            "DistinctReporters":data.get("numDistinctUsers",0),
            "Domain":data.get("domain",""),
            "Status":"OK",
            "Activities":" | ".join(sorted(activities)),
            "Error":""
        }

    except Exception as e:
        return {
            "IP":ip,
            "ScanDate":RUN_DATE,
            "Status":"Error",
            "Error":str(e)
        }

def main():
    if not os.path.exists(INPUT_FILE):
        print("❌ iocs.txt not found")
        return

    with open(INPUT_FILE,encoding="utf-8") as f:
        ips=list(set(x.strip() for x in f if x.strip()))

    results=[]
    for ip in ips:
        print(f"[+] Checking {ip}")
        results.append(check_ip(ip))

    fields=[
        "IP",
        "ScanDate",
        "Reports",
        "Country",
        "ISP",
        "Severity",
        "AbuseScore",
        "ASN",
        "LastReported",
        "UsageType",
        "DistinctReporters",
        "Domain",
        "Status",
        "Activities",
        "Error"
    ]

    with open(OUTPUT_FILE,"w",newline="",encoding="utf-8") as out:
        writer=csv.DictWriter(out,fieldnames=fields,extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print(f"\n🔥 Done -> {OUTPUT_FILE}")

if __name__=="__main__":
    main()
