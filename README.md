# Threat-Hunting-With-API

A collection of Python scripts for threat hunting and IOC enrichment using security APIs.

## What this project does

This repository contains Python-based threat hunting tools that help you:

- Check suspicious IPs, domains, and hashes
- Enrich IOCs with threat intelligence
- Identify indicators linked to malicious activity
- Automate basic investigation tasks using public security APIs

## APIs used

- AbuseIPDB
- AlienVault OTX
- VirusTotal

## Repository structure

- `AbuseIPDB/` — scripts for IP reputation checks
- `AlienVault_OTX/` — scripts for threat intel enrichment
- `VirusTotal/` — scripts for file/hash/domain reputation
- `Sample_IOCs/` — sample indicators for testing
- `README.md` — project overview

## How to use

1. Clone the repository
2. Install the required dependencies
3. Add your API keys if needed
4. Run the script you want to test

Example:

```bash
python AlienVault_OTX/AlienVault_OTX_API.py
