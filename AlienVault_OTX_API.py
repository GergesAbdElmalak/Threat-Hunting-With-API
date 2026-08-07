import csv
import ipaddress
import os
import re
import sys
import urllib3
import requests
from datetime import datetime

from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INPUT_FILE = "iocs.txt"
OUTPUT_FILE = "otx_results.csv"

THREAT_KEYWORDS = [
    "APT","LAZARUS","FIN","TA505","COZY","BEAR","SANDWORM",
    "GRAYCHARLIE","ENERGETIC BEAR","VELVET TEMPEST"
]
#created hidden file on linux and put you api key to wokting with out error
load_dotenv(".env")
API_KEY = os.getenv("OTX_API_KEY")
RUN_DATE = datetime.now().strftime("%d/%m/%Y")

if not API_KEY:
    print("❌ OTX_API_KEY not found in .env")
    sys.exit()

print("✅ API Loaded")

VERIFY_SSL=False
if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session=requests.Session()
session.headers.update({
    "X-OTX-API-KEY":API_KEY,
    "User-Agent":"OTX-IOC-Checker/2.0"
})

retries=Retry(total=3,backoff_factor=1,status_forcelist=[429,500,502,503,504],allowed_methods=["GET"])
adapter=HTTPAdapter(max_retries=retries)
session.mount("https://",adapter)

def is_ip(ioc):
    try:
        ipaddress.ip_address(ioc)
        return True
    except:
        return False

def is_domain(ioc):
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",ioc) is not None

def classify_ioc(ioc):
    if is_ip(ioc): return "IPv4"
    if is_domain(ioc): return "domain"
    return "unknown"

def build_otx_url(ioc):
    t=classify_ioc(ioc)
    if t=="IPv4":
        return f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    if t=="domain":
        return f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
    return None

def extract_threat_actor(pulse):
    found=set()
    adv=pulse.get("adversary","")
    if adv:
        for item in re.split(r"[|,;/]+",str(adv)):
            item=item.strip()
            if item:
                found.add(item)
    for tag in pulse.get("tags",[]):
        up=str(tag).upper()
        if any(k in up for k in THREAT_KEYWORDS):
            found.add(str(tag))
    return sorted(found)

def check_otx(ioc):
    url=build_otx_url(ioc)
    base={
        "IOC":ioc,
        "ScanDate":RUN_DATE,
        "IOC_Type":classify_ioc(ioc),
        "Total_Pulses":"",
        "Checked_Pulses":"",
        "APT_Flag":"NO",
        "Related_Threat_Actors":"",
        "Matched_Pulses":"",
        "Error":""
    }
    if not url:
        base["IOC_Type"]="unknown"
        base["Error"]="Unsupported IOC"
        return base
    try:
        r=session.get(url,timeout=20,verify=VERIFY_SSL)
        if r.status_code!=200:
            base["Error"]=f"HTTP {r.status_code}"
            return base
        data=r.json()
        pulses=data.get("pulse_info",{}).get("pulses",[])
        total=len(pulses)
        actors=set()
        names=[]
        for p in pulses:
            names.append(p.get("name","Unknown"))
            actors.update(extract_threat_actor(p))
        base.update({
            "Total_Pulses":total,
            "Checked_Pulses":total,
            "APT_Flag":"YES" if actors else "NO",
            "Related_Threat_Actors":" | ".join(sorted(actors)),
            "Matched_Pulses":" | ".join(names)
        })
        return base
    except Exception as e:
        base["Error"]=str(e)
        return base

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ {INPUT_FILE} not found")
        return
    with open(INPUT_FILE,encoding="utf-8") as f:
        iocs=[x.strip() for x in f if x.strip()]
    with open(OUTPUT_FILE,"w",newline="",encoding="utf-8") as out:
        writer=csv.DictWriter(out,fieldnames=[
            "IOC","ScanDate","IOC_Type","Total_Pulses","Checked_Pulses",
            "APT_Flag","Related_Threat_Actors","Matched_Pulses","Error"
        ])
        writer.writeheader()
        for ioc in iocs:
            print(f"[+] Checking {ioc}")
            writer.writerow(check_otx(ioc))
    print(f"\n🔥 Done -> {OUTPUT_FILE}")

if __name__=="__main__":
    main()
