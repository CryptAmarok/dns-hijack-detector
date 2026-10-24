# dns-hijack-detector [![Ko-fi](https://img.shields.io/badge/Ko--fi-support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/chrisamarok)
A simple command-line interface (CLI) tool for verifying and analyzing DNS records of a given domain. The script compares local DNS resolution results with trusted DNS over HTTPS (DoH) servers from Cloudflare and Google, and verifies ASN (Autonomous System Number) ownership.

## Features
- Extracts a clean domain name from any given URL.
- Retrieves the local IP address of the domain.
- Verifies the IP address using trusted DoH resolvers (Cloudflare and Google) - You can change it in `dns_checker.py`.
- Retrieves and compares ASN information for the resolved IP addresses using the ipwho.is API.
- Evaluates DNS response consistency and flags potentially suspicious results.

## Requirements
- `requests`
- `dnspython`
You can install them via pip:
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py
```

## Interpreting Results

When checking a domain, the script will output one of the following statuses:

### GOOD: DNS responses are consistent
Local and trusted DNS servers returned the exact same IP address and ASN. The DNS responses are consistent across the local and trusted resolvers.

### GOOD: Possible CDN or load balancing
The IP addresses differ, but the ASNs match. This can be normal when a website uses a CDN or load balancing.

### SUSPICIOUS: DNS responses differ between resolvers
Both the IP addresses and ASNs differ between your local DNS and the trusted servers. This could indicate network censorship, a captive portal (e.g., on public Wi-Fi), or a DNS spoofing attack.

### WARNING: Inconsistent ASN information. Further investigation is required
Matching IP addresses but differing ASNs. This is an unusual edge case that requires manual verification.

## Limitations

This tool identifies potential DNS inconsistencies, but it cannot
definitively detect or confirm DNS hijacking.

Different IP addresses or ASNs do not necessarily indicate an attack.
CDNs, geographic routing, and differences between DNS resolvers can
produce legitimate variations.

Results should be treated as indicators for further investigation,
not as a definitive security assessment.
